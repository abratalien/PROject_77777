import hashlib
import json
import socket
import ssl
import struct
import threading
from Crypto.Cipher import AES
from flask import Flask
from flask_socketio import SocketIO

# ==========================================
# SYSTEM CONFIGURATION
# ==========================================
MASTER_KEY = b"12345678901234567890123456789012"  # 32-Byte Master Key

# PHASE 8: CERTIFICATE CONFIGURATION
CERT_FILE = "receiver.crt"
KEY_FILE = "receiver.key"
CA_FILE = "ca.crt"

# PHASE 9: BLACK BOX AUDIT LOG FILE
BLACKBOX_LOG_FILE = "flight_blackbox.json"

# PHASE 4: PHYSICAL ENGINE SAFETY THRESHOLDS
MAX_SAFE_TEMP_C = 860.0  # Max safe temperature in Celsius
MAX_SAFE_VIB_MMS = 0.05  # Max safe vibration in mm/s
MAX_SAFE_RPM = 13000  # Max safe rotational speed

# Global thread-safe tracking for sequence IDs per engine node
last_seen_sequences = {}
sequence_lock = threading.Lock()

# ==========================================
# PHASE 9: FLASK & WEBSOCKET ENGINE SETUP
# ==========================================
app = Flask(__name__)
app.config["SECRET_KEY"] = "gtre_secret_key"
socketio = SocketIO(app, cors_allowed_origins="*")


# ==========================================
# PHASE 9: HASH-CHAINED AUDIT LOGGER
# ==========================================
class HashChainedAuditLog:
  """Phase 9: Implements a tamper-evident, blockchain-style hash chain log."""

  def __init__(self, log_file=BLACKBOX_LOG_FILE):
    self.log_file = log_file
    self.prev_hash = "0" * 64  # Genesis block hash
    self.lock = threading.Lock()

  def append_record(self, telemetry_payload):
    with self.lock:
      payload_str = json.dumps(telemetry_payload, sort_keys=True)
      combined = (payload_str + self.prev_hash).encode("utf-8")

      current_hash = hashlib.sha256(combined).hexdigest()

      log_entry = {
          "telemetry": telemetry_payload,
          "prev_hash": self.prev_hash,
          "hash": current_hash,
      }

      with open(self.log_file, "a") as f:
        f.write(json.dumps(log_entry) + "\n")

      self.prev_hash = current_hash
      return current_hash


blackbox_logger = HashChainedAuditLog()


def derive_session_key(master_key: bytes, rotation_index: int) -> bytes:
  """Phase 7: Deterministically derives key matching Sender.py."""
  hasher = hashlib.sha256()
  hasher.update(master_key + struct.pack("!I", rotation_index))
  return hasher.digest()


def recv_exact(conn, length):
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
      raw_len = recv_exact(conn, 4)
      if not raw_len:
        print(f"[-] Engine Node at {addr} disconnected.")
        break

      payload_len = int.from_bytes(raw_len, byteorder="big")
      payload = recv_exact(conn, payload_len)

      if not payload or len(payload) < 28:
        continue

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
        print(
            f"❌ DECRYPTION FAILED for {addr}! Invalid Key or Tampered Data.\n"
        )
        continue

      telemetry_payload = json.loads(decrypted_bytes.decode("utf-8"))

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

      # PHASE 9: APPEND TO CRYPTOGRAPHIC HASH-CHAIN LOG
      record_hash = blackbox_logger.append_record(telemetry_payload)

      # PHASE 9 UI: BROADCAST TELEMETRY TO EXTERNAL DASHBOARD FILE
      web_payload = dict(telemetry_payload)
      web_payload["record_hash"] = record_hash
      socketio.emit("telemetry_update", web_payload)

      # Console Render Output
      print(
          f"✅ Node: [{engine_id}] | Packet #{incoming_seq} | Phase:"
          f" {flight_phase} | Time: {ts:.2f}"
      )
      print(
          f"   [CSV Sensors] Temp: {temp}°C | Press: {press} PSI | RPM: {rpm} |"
          f" Vib: {vib} mm/s"
      )
      print(f"   🔒 [Phase 9 Hash Block] {record_hash[:16]}...")

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
  # PHASE 8: ZERO-TRUST mTLS CONTEXT SETUP
  ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
  ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
  ssl_context.load_verify_locations(cafile=CA_FILE)
  ssl_context.verify_mode = ssl.CERT_REQUIRED

  raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  raw_socket.bind(("0.0.0.0", 5000))
  raw_socket.listen(10)

  print(
      "🛡️ Multi-Threaded Receiver with Phase 8 mTLS & Phase 9 Black Box Log"
      " listening on port 5000..."
  )

  try:
    while True:
      raw_conn, addr = raw_socket.accept()
      try:
        tls_conn = ssl_context.wrap_socket(raw_conn, server_side=True)
        client_thread = threading.Thread(
            target=handle_engine_client,
            args=(tls_conn, addr),
            daemon=True,
        )
        client_thread.start()
      except ssl.SSLError as e:
        print(
            f"🚨 [PHASE 8 REJECTED] Unauthorized client connection blocked from"
            f" {addr}: {e}\n"
        )
        raw_conn.close()

  except KeyboardInterrupt:
    print("\n\n⏹️ Receiver stopped by user.")
  finally:
    raw_socket.close()


if __name__ == "__main__":
  # Start TCP mTLS Receiver in background thread
  tcp_thread = threading.Thread(target=start_multi_node_receiver, daemon=True)
  tcp_thread.start()

  # Start SocketIO server for dashboard.html
  print(
      "🌐 Cyber-Physical SocketIO Engine online at http://127.0.0.1:5001."
      " Open dashboard.html!"
  )
  socketio.run(app, host="0.0.0.0", port=5001, allow_unsafe_werkzeug=True)