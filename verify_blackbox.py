import hashlib
import json


def verify_hash_chain(log_file="flight_blackbox.json"):
    print("==================================================")
    print("   GTRE Phase 9 Black Box Log Verification Tool   ")
    print("==================================================\n")

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()

        expected_prev_hash = "0" * 64
        valid_records = 0

        for idx, line in enumerate(lines, 1):
            entry = json.loads(line.strip())
            telemetry = entry["telemetry"]
            prev_hash = entry["prev_hash"]
            stored_hash = entry["hash"]

            # 1. Verify previous hash pointer matches expected state
            if prev_hash != expected_prev_hash:
                print(
                    f"❌ [TAMPER DETECTED] Record #{idx} previous hash pointer"
                    " mismatch!"
                )
                return False

            # 2. Recompute current hash
            payload_str = json.dumps(telemetry, sort_keys=True)
            combined = (payload_str + prev_hash).encode("utf-8")
            recalculated_hash = hashlib.sha256(combined).hexdigest()

            # 3. Validate recalculation against stored hash
            if recalculated_hash != stored_hash:
                print(
                    f"❌ [TAMPER DETECTED] Record #{idx} hash payload mismatch!"
                )
                return False

            expected_prev_hash = stored_hash
            valid_records += 1

        print(
            f"✅ [INTEGRITY OK] All {valid_records} records in '{log_file}' are"
            " cryptographically valid and unbroken."
        )
        return True

    except FileNotFoundError:
        print(f"❌ Error: '{log_file}' does not exist. Run Receiver.py first.")
        return False


if __name__ == "__main__":
    verify_hash_chain()