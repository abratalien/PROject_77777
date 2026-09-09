import hashlib
import json
import socket
import struct
import time
from Crypto.Cipher import AES

MASTER_KEY = b"12345678901234567890123456789012"
RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 5000


def derive_session_key(master_key: bytes, rotation_index: int) -> bytes:
  """Derives the same session key used by Sender and Receiver."""
  hasher = hashlib.sha256()
  hasher.update(master_key + struct.pack("!I", rotation_index))
  return hasher.digest()


def send_frame(sock, data_bytes):
  length_prefix = len(data_bytes).to_bytes(4, byteorder="big")
  sock.sendall(length_prefix + data_bytes)


def attack_1_replay_captured_packet(active_key):
  """ATTACK 1: Replay Attack (Injects Seq #1 for GTRE_GT_01)"""
  print("\n--- 💥 EXECUTING ATTACK 1: Replay Attack on GTRE_GT_01 ---")
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((RECEIVER_HOST, RECEIVER_PORT))

    replayed_payload = {
        "engine_id": "GTRE_GT_01",
        "sequence_id": 1,  # Replaying old packet ID
        "timestamp": time.time(),
        "flight_phase": "REPLAY_INJECTION",
        "temperature_c": 1200.0,
        "pressure_psi": 50.0,
        "rpm": 15000,
        "vibration_mms": 0.15,
    }

    cipher = AES.new(active_key, AES.MODE_GCM)
    ciphertext, auth_tag = cipher.encrypt_and_digest(
        json.dumps(replayed_payload).encode()
    )
    frame = cipher.nonce + auth_tag + ciphertext

    print("📡 Injecting replayed packet (Seq #1) for GTRE_GT_01...")
    send_frame(sock, frame)
    sock.close()
  except Exception as e:
    print(f"[-] Attack 1 failed: {e}")


def attack_2_cross_node_spoofing(active_key):
  """ATTACK 2: Spoofing Attack (Injects replayed Seq #1 claiming to be

  GTRE_GT_02)
  """
  print(
      "\n--- 💥 EXECUTING ATTACK 2: Cross-Node Identity Spoofing (GTRE_GT_02)"
      " ---"
  )
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((RECEIVER_HOST, RECEIVER_PORT))

    spoofed_payload = {
        "engine_id": "GTRE_GT_02",  # Spoofing Engine 02
        "sequence_id": 1,  # Old sequence ID
        "timestamp": time.time(),
        "flight_phase": "SPOOF_INJECTION",
        "temperature_c": 999.9,
        "pressure_psi": 20.0,
        "rpm": 8000,
        "vibration_mms": 0.01,
    }

    cipher = AES.new(active_key, AES.MODE_GCM)
    ciphertext, auth_tag = cipher.encrypt_and_digest(
        json.dumps(spoofed_payload).encode()
    )
    frame = cipher.nonce + auth_tag + ciphertext

    print("📡 Injecting spoofed identity payload for GTRE_GT_02 (Seq #1)...")
    send_frame(sock, frame)
    sock.close()
  except Exception as e:
    print(f"[-] Attack 2 failed: {e}")


def attack_3_corrupt_ciphertext(active_key):
  """ATTACK 3: Tampered Ciphertext Injection"""
  print("\n--- 💥 EXECUTING ATTACK 3: Tampered Ciphertext Injection ---")
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((RECEIVER_HOST, RECEIVER_PORT))

    valid_payload = {
        "engine_id": "GTRE_GT_01",
        "sequence_id": 999,
        "timestamp": time.time(),
        "flight_phase": "TAMPER_TEST",
        "temperature_c": 700.0,
        "pressure_psi": 30.0,
        "rpm": 10000,
        "vibration_mms": 0.02,
    }

    cipher = AES.new(active_key, AES.MODE_GCM)
    ciphertext, auth_tag = cipher.encrypt_and_digest(
        json.dumps(valid_payload).encode()
    )

    # Corrupt last byte of ciphertext
    corrupted_ciphertext = ciphertext[:-1] + b"\xFF"
    tampered_frame = cipher.nonce + auth_tag + corrupted_ciphertext

    print("📡 Sending corrupted ciphertext frame to Receiver...")
    send_frame(sock, tampered_frame)
    sock.close()
  except Exception as e:
    print(f"[-] Attack 3 failed: {e}")


if __name__ == "__main__":
  print("⚠️ STARTING DEFENSIVE VALIDATION SUITE (Attacker.py)...")

  # Match active key rotation index (e.g., index 4 for packets 20-25)
  active_key = derive_session_key(MASTER_KEY, rotation_index=4)

  time.sleep(1)
  attack_1_replay_captured_packet(active_key)
  time.sleep(1)
  attack_2_cross_node_spoofing(active_key)
  time.sleep(1)
  attack_3_corrupt_ciphertext(active_key)
  print("\n🏁 Attacker execution complete. Check Receiver.py output for logs.")