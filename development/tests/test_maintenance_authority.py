"""Real SQLite authority tests. No provider or executor is invoked."""
import hashlib
from contextlib import closing
import importlib.util
import json
import multiprocessing
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import unittest


MODULE = Path(__file__).resolve().parents[1] / "maintenance_authority.py"
SPEC = importlib.util.spec_from_file_location("maintenance_authority_tested", MODULE)
authority = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = authority
SPEC.loader.exec_module(authority)
COMMAND = "a" * 64
EVIDENCE = "b" * 64
OPERATION = "repair_20261027"


def competing_reservation(db, packet_hash, invocation, start, results, evidence=None):
    start.wait(15)
    try:
        result = authority.reserve(db, OPERATION, packet_hash, COMMAND, invocation, evidence)
        results.put(("reserved", result["attempt_number"]))
    except authority.AuthorityError:
        results.put(("denied", None))


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="maintenance-authority-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.db = self.root / "authority.sqlite3"
        authority.initialize(self.db)
        self.packet, self.packet_hash = self.register()

    def register(self, operation=OPERATION, **changes):
        packet = {"operation_id": operation, "repair_attempt_limit": 2,
                  "approved_command_sha256": COMMAND}
        packet.update(changes)
        path = self.root / ("packet-" + str(len(list(self.root.glob("packet-*")))) + ".json")
        raw = json.dumps(packet).encode()
        path.write_bytes(raw)
        authority.register_packet(self.db, path)
        return path, hashlib.sha256(raw).hexdigest()

    def reserve(self, packet_hash=None, invocation="invocation-1", **kwargs):
        return authority.reserve(self.db, OPERATION, packet_hash or self.packet_hash,
                                 COMMAND, invocation, **kwargs)

    def test_initialization_is_explicit_and_create_only(self):
        with self.assertRaises(authority.AuthorityError):
            authority.initialize(self.db)
        missing = self.root / "missing.sqlite3"
        for call in (lambda: authority.check_approval(missing, OPERATION, self.packet_hash, COMMAND),
                     lambda: authority.reserve(missing, OPERATION, self.packet_hash, COMMAND, "call"),
                     lambda: authority.finish(missing, "attempt", "FAILED"),
                     lambda: authority.register_packet(missing, self.packet)):
            with self.assertRaises(authority.AuthorityError):
                call()
            self.assertFalse(missing.exists())

    def test_raw_bytes_and_exact_command_are_bound(self):
        authority.check_approval(self.db, OPERATION, self.packet_hash, COMMAND)
        for op, packet, command in (("other_operation", self.packet_hash, COMMAND),
                                    (OPERATION, "0" * 64, COMMAND),
                                    (OPERATION, self.packet_hash, "c" * 64)):
            with self.assertRaises(authority.AuthorityError):
                authority.check_approval(self.db, op, packet, command)
        self.packet.write_bytes(self.packet.read_bytes() + b"\n")
        changed = hashlib.sha256(self.packet.read_bytes()).hexdigest()
        with self.assertRaises(authority.AuthorityError):
            authority.check_approval(self.db, OPERATION, changed, COMMAND)
        authority.register_packet(self.db, self.packet)
        authority.check_approval(self.db, OPERATION, changed, COMMAND)

    def test_owner_review_digest_binds_exact_enrolled_read(self):
        reviewed = self.packet.read_bytes()
        reviewed_hash = hashlib.sha256(reviewed).hexdigest()
        self.packet.write_bytes(reviewed + b"\n")
        changed_hash = hashlib.sha256(self.packet.read_bytes()).hexdigest()
        for expected in (reviewed_hash, "A" * 64, "invalid"):
            with self.subTest(expected=expected), self.assertRaises(authority.AuthorityError):
                authority.register_packet(self.db, self.packet, expected_sha256=expected)
        with self.assertRaises(authority.AuthorityError):
            authority.check_approval(self.db, OPERATION, changed_hash, COMMAND)
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM approvals").fetchone()[0], 1)
        enrolled = authority.register_packet(self.db, self.packet, expected_sha256=changed_hash)
        self.assertEqual(enrolled["packet_sha256"], changed_hash)
        authority.check_approval(self.db, OPERATION, changed_hash, COMMAND)

    def test_retry_requires_failure_and_separate_registered_evidence(self):
        first = self.reserve()
        self.assertEqual(first["attempt_number"], 1)
        _, retry = self.register(retry_evidence_sha256=EVIDENCE)
        with self.assertRaises(authority.AuthorityError):
            self.reserve(retry, "invocation-2", retry_evidence_sha256=EVIDENCE)
        authority.finish(self.db, first["attempt_id"], "FAILED")
        for packet, evidence in ((self.packet_hash, None), (retry, None), (retry, "c" * 64)):
            with self.assertRaises(authority.AuthorityError):
                self.reserve(packet, "invocation-2", retry_evidence_sha256=evidence)
        second = self.reserve(retry, "invocation-2", retry_evidence_sha256=EVIDENCE)
        self.assertEqual(second["attempt_number"], 2)
        authority.finish(self.db, second["attempt_id"], "FAILED")
        _, revised = self.register(retry_evidence_sha256="c" * 64, revision=3)
        with self.assertRaises(authority.AuthorityError):
            self.reserve(revised, "invocation-3", retry_evidence_sha256="c" * 64)
        context = multiprocessing.get_context("spawn")
        start, results = context.Event(), context.Queue()
        restarted = context.Process(target=competing_reservation,
                    args=(str(self.db), revised, "restarted-call", start, results, "c" * 64))
        restarted.start()
        start.set()
        self.assertEqual(results.get(timeout=30), ("denied", None))
        restarted.join(30)
        self.assertEqual(restarted.exitcode, 0)

    def test_first_packet_cannot_be_reused_as_retry_even_with_evidence(self):
        _, packet = self.register(retry_evidence_sha256=EVIDENCE)
        first = self.reserve(packet, retry_evidence_sha256=EVIDENCE)
        authority.finish(self.db, first["attempt_id"], "FAILED")
        with self.assertRaises(authority.AuthorityError):
            self.reserve(packet, "invocation-2", retry_evidence_sha256=EVIDENCE)

    def test_changed_packets_and_restart_never_reset_budget(self):
        first = self.reserve()
        authority.finish(self.db, first["attempt_id"], "FAILED")
        authority.register_packet(self.db, self.packet)
        _, revised = self.register(revision=2)
        with self.assertRaises(authority.AuthorityError):
            self.reserve(revised, "invocation-2")
        # A newly loaded module represents a fresh process/session, with no memory.
        fresh_spec = importlib.util.spec_from_file_location("fresh_authority", MODULE)
        fresh = importlib.util.module_from_spec(fresh_spec)
        fresh_spec.loader.exec_module(fresh)
        with self.assertRaises(fresh.AuthorityError):
            fresh.reserve(self.db, OPERATION, revised, COMMAND, "new-session")

    def test_replay_is_global_and_never_reallowed(self):
        first = self.reserve(invocation="shared-call")
        authority.finish(self.db, first["attempt_id"], "FAILED")
        _, second_packet = self.register("different_operation")
        with self.assertRaises(authority.AuthorityError):
            authority.reserve(self.db, "different_operation", second_packet, COMMAND, "shared-call")

    def test_success_unknown_and_unresolved_block_later_attempts(self):
        for outcome in (None, "UNKNOWN", "SUCCEEDED"):
            with self.subTest(outcome=outcome):
                op = "operation_" + str(outcome)
                _, packet = self.register(op)
                first = authority.reserve(self.db, op, packet, COMMAND, "first-" + str(outcome))
                if outcome:
                    authority.finish(self.db, first["attempt_id"], outcome)
                _, retry = self.register(op, retry_evidence_sha256=EVIDENCE)
                with self.assertRaises(authority.AuthorityError):
                    authority.reserve(self.db, op, retry, COMMAND, "next-" + str(outcome), EVIDENCE)

    def test_finish_is_append_once_and_never_changes_unknown(self):
        first = self.reserve()
        authority.finish(self.db, first["attempt_id"], "UNKNOWN")
        authority.finish(self.db, first["attempt_id"], "UNKNOWN")
        for attempt, outcome in ((first["attempt_id"], "FAILED"),
                                 ("missing-attempt", "FAILED"), (first["attempt_id"], "invalid")):
            with self.assertRaises(authority.AuthorityError):
                authority.finish(self.db, attempt, outcome)

    def test_invalid_registration_is_rejected(self):
        for changes in ({"operation_id": "../oops"}, {"operation_id": "short"},
                        {"repair_attempt_limit": 3}, {"repair_attempt_limit": 2.0},
                        {"approved_command_sha256": "A" * 64},
                        {"retry_evidence_sha256": None}, {"retry_evidence_sha256": ""}):
            with self.subTest(changes=changes), self.assertRaises(authority.AuthorityError):
                self.register(**changes)
        for raw in (b"[]", b"invalid", b'{"operation_id":"operation_one","operation_id":"operation_two"}'):
            self.packet.write_bytes(raw)
            with self.assertRaises(authority.AuthorityError):
                authority.register_packet(self.db, self.packet)

    def test_corruption_wrong_schema_and_malformed_rows_fail_closed(self):
        for mutation in ("PRAGMA user_version = 77", "PRAGMA application_id = 0",
                         "CREATE TABLE surprise(value TEXT)",
                         "DROP TRIGGER no_update_operations",
                         "INSERT INTO operations VALUES('bad',2,'2026-10-27T00:00:00+00:00')",
                         "INSERT INTO approvals VALUES('" + "b" * 64 + "','missing_operation','" + COMMAND + "',NULL,'2026-10-27T00:00:00+00:00')"):
            with self.subTest(mutation=mutation):
                damaged = self.root / ("damaged-" + str(len(list(self.root.glob("damaged-*")))) + ".sqlite3")
                damaged.write_bytes(self.db.read_bytes())
                with closing(sqlite3.connect(damaged)) as connection:
                    connection.execute(mutation)
                    connection.commit()
                with self.assertRaises(authority.AuthorityError):
                    authority.check_approval(damaged, OPERATION, self.packet_hash, COMMAND)
        self.db.write_bytes(b"not SQLite")
        with self.assertRaises(authority.AuthorityError):
            self.reserve()

    def test_readonly_and_directory_storage_fail_closed(self):
        original = self.db.stat().st_mode
        self.db.chmod(stat.S_IREAD)
        try:
            with self.assertRaises(authority.AuthorityError):
                self.reserve()
        finally:
            self.db.chmod(original | stat.S_IWRITE)
        with self.assertRaises(authority.AuthorityError):
            authority.reserve(self.root, OPERATION, self.packet_hash, COMMAND, "call")

    def test_lost_outcome_write_keeps_reservation_blocked(self):
        first = self.reserve()
        original = self.db.stat().st_mode
        self.db.chmod(stat.S_IREAD)
        try:
            with self.assertRaises(authority.AuthorityError):
                authority.finish(self.db, first["attempt_id"], "FAILED")
        finally:
            self.db.chmod(original | stat.S_IWRITE)
        _, retry = self.register(retry_evidence_sha256=EVIDENCE)
        with self.assertRaises(authority.AuthorityError):
            self.reserve(retry, "next-call", retry_evidence_sha256=EVIDENCE)
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM attempts").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM outcomes").fetchone()[0], 0)

    def test_locked_database_never_provides_authority(self):
        with closing(sqlite3.connect(self.db, isolation_level=None)) as connection:
            connection.execute("BEGIN EXCLUSIVE")
            try:
                with self.assertRaises(authority.AuthorityError):
                    self.reserve()
            finally:
                connection.rollback()
        self.assertEqual(self.reserve()["attempt_number"], 1)

    def test_ledger_rows_cannot_be_updated_or_deleted(self):
        first = self.reserve()
        authority.finish(self.db, first["attempt_id"], "FAILED")
        with closing(sqlite3.connect(self.db)) as connection:
            for table in ("operations", "approvals", "attempts", "outcomes"):
                for statement in ("DELETE FROM " + table, "UPDATE " + table + " SET created_utc='changed'"):
                    with self.subTest(statement=statement), self.assertRaises(sqlite3.DatabaseError):
                        connection.execute(statement)

    def test_symlink_db_or_ancestor_is_rejected(self):
        link = self.root / "linked.sqlite3"
        try:
            link.symlink_to(self.db)
        except OSError:
            self.skipTest("Host does not permit creating symlinks")
        with self.assertRaises(authority.AuthorityError):
            authority.check_approval(link, OPERATION, self.packet_hash, COMMAND)
        folder = self.root / "alias"
        folder.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(authority.AuthorityError):
            authority.check_approval(folder / self.db.name, OPERATION, self.packet_hash, COMMAND)

    def test_competing_processes_get_only_one_reservation(self):
        context = multiprocessing.get_context("spawn")
        start, results = context.Event(), context.Queue()
        processes = [context.Process(target=competing_reservation,
                     args=(str(self.db), self.packet_hash, "concurrent-" + str(i), start, results))
                     for i in range(4)]
        for process in processes:
            process.start()
        start.set()
        answers = [results.get(timeout=30) for _ in processes]
        for process in processes:
            process.join(30)
            self.assertEqual(process.exitcode, 0)
        self.assertEqual(answers.count(("reserved", 1)), 1)
        self.assertEqual(answers.count(("denied", None)), 3)


if __name__ == "__main__":
    unittest.main()
