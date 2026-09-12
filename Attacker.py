import hashlib
import json
import socket
import ssl
import struct
import time
from Crypto.Cipher import AES

MASTER_KEY = b"12345678901234567890123456789012"
RECEIVER_HOST = "127.0.0.1"
RECEIVER_PORT = 5000

# PHASE 8: mTLS CERTIFICATE CONFIGURATION
CERT_FILE = "sender.crt"
KEY_FILE = "sender.key"
CA_FILE = "ca.crt"


def derive_session_key(master_key: bytes, rotation_index: int) -> bytes:
    """Derives the same session key used by Sender and Receiver."""
    hasher = hashlib.sha256()
    hasher.update(master_key + struct.pack("!I", rotation_index))
    return hasher.digest()


def create_mtls_socket():
    """Helper function to create a socket wrapped with Phase 8 mTLS credentials."""
    ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    ssl_context.load_verify_locations(cafile=CA_FILE)
    ssl_context.check_hostname = False

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mtls_socket = ssl_context.wrap_socket(
        raw_socket, server_hostname="ReceiverNode"
    )
    mtls_socket.connect((RECEIVER_HOST, RECEIVER_PORT))
    return mtls_socket


def send_frame(sock, data_bytes):
    length_prefix = len(data_bytes).to_bytes(4, byteorder="big")
    sock.sendall(length_prefix + data_bytes)


def attack_0_unauthorized_mtls_bypass():
    """ATTACK 0 (PHASE 8 TEST): Plain TCP Connection without mTLS Certificates."""
    print(
        "\n--- 💥 EXECUTING ATTACK 0: Unauthorized Connection (Phase 8 mTLS"
        " Bypass) ---"
    )
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw_socket.connect((RECEIVER_HOST, RECEIVER_PORT))
        # Send raw dummy data without mTLS handshake
        raw_socket.sendall(b"\x00\x00\x00\x20" + b"A" * 32)
        print(
            "⚠️ [FAIL] Plain socket connected (Receiver failed to enforce"
            " Phase 8 mTLS)."
        )
    except (ConnectionResetError, ssl.SSLError):
        print(
            "🛡️ [SUCCESS] Phase 8 Defense Active: Receiver immediately"
            " rejected unauthenticated socket!"
        )
    except ConnectionRefusedError:
        print("❌ Error: Receiver is not online on port 5000.")
    finally:
        raw_socket.close()


def attack_1_replay_captured_packet(active_key):
    """ATTACK 1: Replay Attack (Injects Seq #1 for GTRE_GT_01)."""
    print("\n--- 💥 EXECUTING ATTACK 1: Replay Attack on GTRE_GT_01 ---")
    try:
        # Passes Phase 8 mTLS using valid certs, but tests Phase 6 anti-replay gate
        sock = create_mtls_socket()

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
    """ATTACK 2: Spoofing Attack (Injects replayed Seq #1 claiming to be GTRE_GT_02)."""
    print(
        "\n--- 💥 EXECUTING ATTACK 2: Cross-Node Identity Spoofing (GTRE_GT_02)"
        " ---"
    )
    try:
        sock = create_mtls_socket()

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
    """ATTACK 3: Tampered Ciphertext Injection."""
    print("\n--- 💥 EXECUTING ATTACK 3: Tampered Ciphertext Injection ---")
    try:
        sock = create_mtls_socket()

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
    # Test Phase 8 mTLS enforcement
    attack_0_unauthorized_mtls_bypass()
    time.sleep(1)

    # Test Phase 2, Phase 3, and Phase 6 protections over mTLS
    attack_1_replay_captured_packet(active_key)
    time.sleep(1)
    attack_2_cross_node_spoofing(active_key)
    time.sleep(1)
    attack_3_corrupt_ciphertext(active_key)

    print(
        "\n🏁 Attacker execution complete. Check Receiver.py output for logs."
    )