import csv
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
from Crypto.Cipher import AES

MASTER_KEY = b"12345678901234567890123456789012"  # 32-Byte Key
ROTATION_INTERVAL = 5  # Re-key every 5 packets

# PHASE 8: mTLS CERTIFICATE PATHS
CERT_FILE = "sender.crt"
KEY_FILE = "sender.key"
CA_FILE = "ca.crt"


def derive_session_key(master_key: bytes, rotation_index: int) -> bytes:
    """Phase 7: Deterministically derives the symmetric key matching Receiver.py."""
    hasher = hashlib.sha256()
    hasher.update(master_key + struct.pack("!I", rotation_index))
    return hasher.digest()


# Phase 6: Engine ID CLI override or CSV default
engine_id_override = sys.argv[1] if len(sys.argv) > 1 else None
csv_filename = "r_e_t.csv"

# --- PHASE 8: ZERO-TRUST mTLS SOCKET WRAPPER ---
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
ssl_context.load_verify_locations(cafile=CA_FILE)
ssl_context.check_hostname = False  # Set to True if using valid hostname matching CN in certificate

raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

try:
    # Wrap standard TCP socket in TLS client layer
    sender_socket = ssl_context.wrap_socket(
        raw_socket, server_hostname="ReceiverNode"
    )
    sender_socket.connect(("127.0.0.1", 5000))
    print("[Phase 8 mTLS SUCCESS] Mutual TLS connection verified with Receiver.")
except ssl.SSLError as e:
    print(f"❌ [Phase 8 mTLS ERROR] Failed mTLS Handshake with Receiver: {e}")
    sys.exit(1)
except ConnectionRefusedError:
    print("❌ Error: Receiver is not online on port 5000.")
    sys.exit(1)

print(f"🚀 Sender streaming directly from '{csv_filename}'...")

packet_sequence = 0
packet_count = 0
rotation_index = 0
current_key = derive_session_key(MASTER_KEY, rotation_index)

try:
    with open(csv_filename, mode="r") as file:
        reader = csv.DictReader(file)

        for row in reader:
            packet_sequence += 1

            # PHASE 7: Dynamic Rekeying Check
            if packet_count > 0 and packet_count % ROTATION_INTERVAL == 0:
                rotation_index += 1
                current_key = derive_session_key(MASTER_KEY, rotation_index)
                print(
                    f"\n🔑 [KEY ROTATION] Switched to Key Index #{rotation_index} ->"
                    f" {current_key.hex()[:8]}...\n"
                )

            node_id = (
                engine_id_override if engine_id_override else row.get("engine_id")
            )

            # Construct JSON payload directly from CSV row values
            telemetry_payload = {
                "sequence_id": packet_sequence,
                "timestamp": float(row["timestamp"]),
                "engine_id": node_id,
                "flight_phase": row["flight_phase"],
                "temperature_c": float(row["temperature_c"]),
                "pressure_psi": float(row["pressure_psi"]),
                "rpm": int(row["rpm"]),
                "vibration_mms": float(row["vibration_mms"]),
            }

            # AES-256-GCM Encryption
            raw_bytes = json.dumps(telemetry_payload).encode("utf-8")
            nonce = os.urandom(12)  # 12-byte GCM Nonce
            cipher = AES.new(current_key, AES.MODE_GCM, nonce=nonce)
            ciphertext, auth_tag = cipher.encrypt_and_digest(raw_bytes)

            # Wire Frame: [4B Length Header] + [12B Nonce] + [16B Auth Tag] + [Ciphertext]
            payload = nonce + auth_tag + ciphertext
            length_header = len(payload).to_bytes(4, byteorder="big")
            wire_packet = length_header + payload

            # Transmit secure packet over mTLS tunnel
            sender_socket.sendall(wire_packet)
            packet_count += 1

            print(
                f"📡 Sent Node [{node_id}] Packet #{packet_sequence} | Phase:"
                f" {row['flight_phase']} | Temp: {row['temperature_c']}°C | Vib:"
                f" {row['vibration_mms']}mm/s"
            )

            time.sleep(0.5)  # Transmit row every 500ms

except FileNotFoundError:
    print(
        f"❌ Error: '{csv_filename}' not found. Please place the CSV in this"
        " directory."
    )
except KeyboardInterrupt:
    print("\n\n⏹️ CSV Transmission stopped by user (Ctrl+C).")
finally:
    sender_socket.close()