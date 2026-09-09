import hashlib
import json
import socket
import struct
import threading
from Crypto.Cipher import AES

MASTER_KEY = b"12345678901234567890123456789012"  # 32-Byte Master Key

# PHASE 4: PHYSICAL ENGINE SAFETY THRESHOLDS
MAX_SAFE_TEMP_C = 860.0  # Max safe temperature in Celsius
MAX_SAFE_VIB_MMS = 0.05  # Max safe vibration in mm/s
MAX_SAFE_RPM = 13000  # Max safe rotational speed

# Global thread-safe tracking for sequence IDs per engine node
last_seen_sequences = {}
sequence_lock = threading.Lock()


def derive_session_key(master_key: bytes, rotation_index: int) -> bytes:
  """Phase 7: Deterministically derives key matching Sender.py."""
  hasher = hashlib.sha256()
  hasher.update(master_key + struct.pack("!I", rotation_index))
  return hasher.digest()


def recv_exact(conn, length):
  """Helper to ensure exact byte counts are read from TCP stream."""
  buf = b""
  while len(buf) < length:
    chunk = conn.recv(length - len(buf))
    if not chunk:
      return None
    buf += chunk
  return buf


def handle_engine_client(conn, addr):
  """Worker function to handle each connected engine node in its own thread."""
  print(f"✅ Connection established with Engine Node at {addr}\n")

  try:
    while True:
      # Read 4-byte length header
      raw_len = recv_exact(conn, 4)
      if not raw_len:
        print(f"[-] Engine Node at {addr} disconnected.")
        break

      payload_len = int.from_bytes(raw_len, byteorder="big")
      payload = recv_exact(conn, payload_len)

      if not payload or len(payload) < 28:
        continue

      # Unpack Nonce, Auth Tag, Ciphertext
      nonce = payload[:12]
      auth_tag = payload[12:28]
      ciphertext = payload[28:]

      # Phase 7: Key Derivation Trial Sync
      decrypted_bytes = None
      for trial_index in range(0, 100):
        trial_key = derive_session_key(MASTER_KEY, trial_index)
        try:
          cipher = AES.new(trial_key, AES.MODE_GCM, nonce=nonce)
          decrypted_bytes = cipher.decrypt_and_verify(ciphertext, auth_tag)
          break
        except ValueError:
          continue

      if decrypted_bytes is None:
        print(f"❌ DECRYPTION FAILED for {addr}! Invalid Key or Tampered Data.\n")
        continue

      telemetry_payload = json.loads(decrypted_bytes.decode("utf-8"))

      # Extract CSV telemetry fields
      engine_id = telemetry_payload.get("engine_id", "UNKNOWN_NODE")
      incoming_seq = telemetry_payload["sequence_id"]
      ts = telemetry_payload["timestamp"]
      flight_phase = telemetry_payload.get("flight_phase", "UNKNOWN")
      temp = telemetry_payload["temperature_c"]
      press = telemetry_payload["pressure_psi"]
      rpm = telemetry_payload["rpm"]
      vib = telemetry_payload["vibration_mms"]

      # Thread-Safe Phase 6 Anti-Replay Gate per Node
      with sequence_lock:
        last_seq = last_seen_sequences.get(engine_id, 0)
        if incoming_seq <= last_seq:
          print(
              f"⚠️ REPLAY/OUT-OF-ORDER ALERT! Node: [{engine_id}] | Dropped"
              f" Packet ID: {incoming_seq}"
          )
          continue
        last_seen_sequences[engine_id] = incoming_seq

      # Render Telemetry Data Output
      print(
          f"✅ Node: [{engine_id}] | Packet #{incoming_seq} | Phase:"
          f" {flight_phase} | Time: {ts:.2f}"
      )
      print(
          f"   [CSV Sensors] Temp: {temp}°C | Press: {press} PSI | RPM: {rpm}"
          f" | Vib: {vib} mm/s"
      )

      # PHASE 4: PHYSICAL ANOMALY EVALUATION
      has_anomaly = False
      if temp > MAX_SAFE_TEMP_C:
        print(
            f"   🚨 [ANOMALY] Thermal Spike Detected: {temp}°C (Limit:"
            f" {MAX_SAFE_TEMP_C}°C)"
        )
        has_anomaly = True
      if vib > MAX_SAFE_VIB_MMS:
        print(
            f"   🚨 [ANOMALY] Excessive Vibration: {vib} mm/s (Limit:"
            f" {MAX_SAFE_VIB_MMS} mm/s)"
        )
        has_anomaly = True
      if rpm > MAX_SAFE_RPM:
        print(
            f"   🚨 [ANOMALY] Engine Overspeed: {rpm} RPM (Limit:"
            f" {MAX_SAFE_RPM} RPM)"
        )
        has_anomaly = True

      if not has_anomaly:
        print("   💚 [SYSTEM HEALTH] Nominal Operating Parameters")

      print()

  except Exception as e:
    print(f"[-] Error handling client {addr}: {e}")
  finally:
    conn.close()


def start_multi_node_receiver():
  receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  receiver_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  receiver_socket.bind(("0.0.0.0", 5000))
  receiver_socket.listen(10)

  print(
      "🛡️ Multi-Threaded Receiver listening on port 5000 (Parallel Engine"
      " Processing)..."
  )

  try:
    while True:
      conn, addr = receiver_socket.accept()
      # Spawn a new background thread for each connected engine node
      client_thread = threading.Thread(
          target=handle_engine_client, args=(conn, addr), daemon=True
      )
      client_thread.start()
  except KeyboardInterrupt:
    print("\n\n⏹️ Receiver stopped by user (Ctrl+C).")
  finally:
    receiver_socket.close()


if __name__ == "__main__":
  start_multi_node_receiver()