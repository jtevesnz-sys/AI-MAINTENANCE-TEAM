"""Demonstrate the real attempt ledger with fictional data, not repairs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "development"))
import maintenance_authority as authority


def main():
    print("SIMULATED maintenance: an imaginary service is unavailable")
    print("Janitor: record the issue and propose a repair for owner review")
    operation = "demo_repair_001"
    command_hash = hashlib.sha256(b"fictional repair; never executed").hexdigest()
    evidence_hash = hashlib.sha256(b"fictional failure evidence").hexdigest()
    with tempfile.TemporaryDirectory(prefix="maintenance-demo-") as directory:
        root = Path(directory)
        database = root / "authority.sqlite3"
        authority.initialize(database)

        def register(name, **extra):
            packet = {"operation_id": operation, "repair_attempt_limit": 2,
                      "approved_command_sha256": command_hash, **extra}
            path = root / name
            data = json.dumps(packet, sort_keys=True).encode("utf-8")
            path.write_bytes(data)
            authority.register_packet(database, path)
            return hashlib.sha256(data).hexdigest()

        initial = register("approval.json")
        print("Owner: register a fictional approval for the demonstration")
        first = authority.reserve(database, operation, initial, command_hash, "demo-1")
        authority.finish(database, first["attempt_id"], "FAILED")
        print("Technician: Attempt 1: FAILED (simulated)")

        retry = register("retry.json", retry_evidence_sha256=evidence_hash)
        second = authority.reserve(database, operation, retry, command_hash, "demo-2", evidence_hash)
        authority.finish(database, second["attempt_id"], "FAILED")
        print("Technician: Attempt 2: FAILED (simulated; evidence supplied)")

        third = register("third.json", retry_evidence_sha256=evidence_hash, revision=3)
        try:
            authority.reserve(database, operation, third, command_hash, "demo-3", evidence_hash)
        except authority.AuthorityError as error:
            if str(error) != "Two-total-attempt budget is exhausted":
                raise
            print("Technician: Attempt 3: BLOCKED by the two-attempt ledger")
        else:
            raise RuntimeError("The attempt limit did not block a third reservation")
    print("No real repair was run. Temporary demonstration data was removed.")


if __name__ == "__main__":
    main()
