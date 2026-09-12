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
        print("✅ Replay packet injected.")
    except Exception as e:
        print(f"[-] Attack 1 failed: {e}")


def attack_2_false_key_spoofing():
    """ATTACK 2: False Key / Cross-Node Spoofing Attack.
    Uses an INVALID key so decryption trial fails at Receiver.
    """
    print(
        "\n--- 💥 EXECUTING ATTACK 2: False Key / Identity Spoofing Injection"
        " ---"
    )
    try:
        sock = create_mtls_socket()

        # False key that won't match any session key index 0-99
        bogus_key = b"BAD_KEY_999999999999999999999999"

        spoofed_payload = {
            "engine_id": "GTRE_GT_02",
            "sequence_id": 1,
            "timestamp": time.time(),
            "flight_phase": "FALSE_KEY_INJECTION",
            "temperature_c": 999.9,
            "pressure_psi": 20.0,
            "rpm": 8000,
            "vibration_mms": 0.01,
        }

        cipher = AES.new(bogus_key, AES.MODE_GCM)
        ciphertext, auth_tag = cipher.encrypt_and_digest(
            json.dumps(spoofed_payload).encode()
        )
        frame = cipher.nonce + auth_tag + ciphertext

        print("📡 Injecting payload encrypted with FALSE KEY...")
        send_frame(sock, frame)
        sock.close()
        print("✅ False key packet injected.")
    except Exception as e:
        print(f"[-] Attack 2 failed: {e}")


def attack_3_corrupt_ciphertext_once(active_key):
    """ATTACK 3: Single Data Tampering Attack (Corrupts Ciphertext)."""
    print(
        "\n--- 💥 EXECUTING ATTACK 3: Single Data Tampering Attack (One-Time"
        " Bit-Flip) ---"
    )
    try:
        sock = create_mtls_socket()

        valid_payload = {
            "engine_id": "GTRE_GT_01",
            "sequence_id": 999,
            "timestamp": time.time(),
            "flight_phase": "SINGLE_TAMPER_TEST",
            "temperature_c": 700.0,
            "pressure_psi": 30.0,
            "rpm": 10000,
            "vibration_mms": 0.02,
        }

        cipher = AES.new(active_key, AES.MODE_GCM)
        ciphertext, auth_tag = cipher.encrypt_and_digest(
            json.dumps(valid_payload).encode()
        )

        # Corrupt exactly the last byte of ciphertext (One-time tampering)
        corrupted_ciphertext = ciphertext[:-1] + b"\xFF"
        tampered_frame = cipher.nonce + auth_tag + corrupted_ciphertext

        print("📡 Injecting ONE tampered ciphertext frame to Receiver...")
        send_frame(sock, tampered_frame)
        sock.close()
        print("✅ Single tampered packet injected.")
    except Exception as e:
        print(f"[-] Attack 3 failed: {e}")


if __name__ == "__main__":
    print("⚠️ STARTING DEFENSIVE VALIDATION SUITE (Attacker.py)...")

    # Match active key rotation index (e.g., index 0 for current session)
    active_key = derive_session_key(MASTER_KEY, rotation_index=0)

    # 1. Test Phase 8 mTLS Enforcement
    time.sleep(1)
    attack_0_unauthorized_mtls_bypass()

    # 2. Test Phase 6 Anti-Replay Defense
    time.sleep(1)
    attack_1_replay_captured_packet(active_key)

    # 3. Test Phase 7 False Key Defense
    time.sleep(1)
    attack_2_false_key_spoofing()

    # 4. Test Phase 2 Data Integrity Defense (Exactly ONCE)
    time.sleep(1)
    attack_3_corrupt_ciphertext_once(active_key)

    print(
        "\n🏁 Attacker execution complete! All 4 attack vectors executed."
        " Check Receiver.py output for defense logs."
    )