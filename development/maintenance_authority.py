"""Owner-enrolled approval hashes and a durable, two-attempt Maintenance ledger.

Initialization and registration are owner/operator actions, never agent tools.
Deployment must restrict the database and its directory to trusted principals;
SQLite cannot authenticate the owner or protect against an administrator editing
its bytes. Runtime APIs never create storage or refund uncertain attempts.
"""
from __future__ import annotations

from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid


class AuthorityError(Exception):
    """Authority or durable accounting is unavailable; execution must stop."""


APPLICATION_ID = 0x4D41494E
SCHEMA_VERSION = 1
_OPERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,79}\Z")
_INVOCATION = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ATTEMPT = re.compile(r"[0-9a-f]{32}\Z")
_OUTCOMES = {"SUCCEEDED", "FAILED", "UNKNOWN"}

_SCHEMA = {
    "operations": """CREATE TABLE operations (
operation_id TEXT PRIMARY KEY NOT NULL,
repair_attempt_limit INTEGER NOT NULL CHECK(repair_attempt_limit=2),
created_utc TEXT NOT NULL)""",
    "approvals": """CREATE TABLE approvals (
packet_sha256 TEXT PRIMARY KEY NOT NULL,
operation_id TEXT NOT NULL REFERENCES operations(operation_id),
command_sha256 TEXT NOT NULL,
retry_evidence_sha256 TEXT,
created_utc TEXT NOT NULL)""",
    "attempts": """CREATE TABLE attempts (
attempt_id TEXT PRIMARY KEY NOT NULL,
operation_id TEXT NOT NULL REFERENCES operations(operation_id),
packet_sha256 TEXT NOT NULL REFERENCES approvals(packet_sha256),
command_sha256 TEXT NOT NULL,
invocation_id TEXT NOT NULL UNIQUE,
attempt_number INTEGER NOT NULL CHECK(attempt_number IN (1,2)),
retry_evidence_sha256 TEXT,
created_utc TEXT NOT NULL,
UNIQUE(operation_id,attempt_number))""",
    "outcomes": """CREATE TABLE outcomes (
attempt_id TEXT PRIMARY KEY NOT NULL REFERENCES attempts(attempt_id),
outcome TEXT NOT NULL CHECK(outcome IN ('SUCCEEDED','FAILED','UNKNOWN')),
created_utc TEXT NOT NULL)""",
}
for _table in tuple(_SCHEMA):
    for _action in ("UPDATE", "DELETE"):
        _name = "no_" + _action.lower() + "_" + _table
        _SCHEMA[_name] = (
            f"CREATE TRIGGER {_name} BEFORE {_action} ON {_table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable authority history'); END")


def _require(value, pattern, label):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AuthorityError("Invalid " + label)
    return value


def _hash(value, label="SHA-256"):
    return _require(value, _HASH, label)


def _evidence(value):
    if value is not None:
        _hash(value, "retry evidence SHA-256")


def _utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _timestamp(value):
    try:
        parsed = dt.datetime.fromisoformat(value)
        if parsed.utcoffset() != dt.timedelta(0):
            raise ValueError
    except (TypeError, ValueError):
        raise AuthorityError("Malformed authority timestamp") from None


def _path(value, *, missing=False):
    """Reject links/junctions without resolving them into trusted paths."""
    try:
        path = Path(os.path.abspath(os.fspath(value)))
        for component in (*reversed(path.parents), path):
            try:
                info = component.lstat()
            except FileNotFoundError:
                if missing and component == path:
                    continue
                raise AuthorityError("Authority storage path is unavailable") from None
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise AuthorityError("Authority storage cannot use links or reparse points")
            if component != path and not stat.S_ISDIR(info.st_mode):
                raise AuthorityError("Authority storage parent is not a directory")
        if path.exists():
            info = path.stat()
            if not stat.S_ISREG(info.st_mode):
                raise AuthorityError("Authority storage is not a regular file")
            if not info.st_mode & 0o222 or getattr(info, "st_file_attributes", 0) & 1:
                raise AuthorityError("Authority storage is read-only")
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(path) + suffix)
            if sidecar.is_symlink():
                raise AuthorityError("Authority journal cannot be a link")
            if sidecar.exists():
                info = sidecar.lstat()
                if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    raise AuthorityError("Authority journal path is unsafe")
        return path
    except (OSError, TypeError, ValueError) as exc:
        raise AuthorityError("Authority storage path is unavailable") from exc


def _connect(path):
    connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True,
                                 timeout=5, isolation_level=None)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA trusted_schema=OFF")
    except BaseException:
        connection.close()
        raise
    return connection


def initialize(path):
    """Create a registry once. Existing files, including invalid files, are kept."""
    target = _path(path, missing=True)
    connection = None
    try:
        descriptor = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
        connection = _connect(target)
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        for sql in _SCHEMA.values():
            connection.execute(sql)
        connection.commit()
    except (OSError, sqlite3.Error) as exc:
        raise AuthorityError("Authority initialization failed; existing storage was not replaced") from exc
    finally:
        if connection is not None:
            connection.close()


def _validate(connection):
    if (connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION):
        raise AuthorityError("Authority database identity or version is invalid")
    actual = dict(connection.execute(
        "SELECT name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*'"))
    if actual != _SCHEMA:
        raise AuthorityError("Authority schema is invalid")
    if [row[0] for row in connection.execute("PRAGMA quick_check")] != ["ok"]:
        raise AuthorityError("Authority database is corrupt")
    if connection.execute("PRAGMA foreign_key_check").fetchone():
        raise AuthorityError("Authority history has invalid references")
    operations = {}
    for row in connection.execute("SELECT * FROM operations"):
        _require(row["operation_id"], _OPERATION, "operation identity")
        if type(row["repair_attempt_limit"]) is not int or row["repair_attempt_limit"] != 2:
            raise AuthorityError("Authority attempt budget is invalid")
        _timestamp(row["created_utc"])
        operations[row["operation_id"]] = []
    approvals = {}
    for row in connection.execute("SELECT * FROM approvals"):
        _hash(row["packet_sha256"])
        _hash(row["command_sha256"])
        _evidence(row["retry_evidence_sha256"])
        _timestamp(row["created_utc"])
        approvals[row["packet_sha256"]] = row
    outcomes = {}
    for row in connection.execute("SELECT * FROM outcomes"):
        if row["outcome"] not in _OUTCOMES:
            raise AuthorityError("Authority outcome is invalid")
        _timestamp(row["created_utc"])
        outcomes[row["attempt_id"]] = row["outcome"]
    for row in connection.execute("SELECT * FROM attempts ORDER BY operation_id,attempt_number"):
        _require(row["attempt_id"], _ATTEMPT, "attempt identity")
        _require(row["invocation_id"], _INVOCATION, "invocation identity")
        _timestamp(row["created_utc"])
        approval = approvals[row["packet_sha256"]]
        history = operations[row["operation_id"]]
        if (approval["operation_id"] != row["operation_id"]
                or approval["command_sha256"] != row["command_sha256"]
                or approval["retry_evidence_sha256"] != row["retry_evidence_sha256"]
                or type(row["attempt_number"]) is not int
                or row["attempt_number"] != len(history) + 1 or len(history) >= 2):
            raise AuthorityError("Authority attempt history is inconsistent")
        if history and (outcomes.get(history[0]["attempt_id"]) != "FAILED"
                        or row["packet_sha256"] == history[0]["packet_sha256"]
                        or not row["retry_evidence_sha256"]):
            raise AuthorityError("Authority retry history is inconsistent")
        history.append(row)


@contextmanager
def _transaction(path):
    connection = None
    try:
        connection = _connect(_path(path))
        connection.execute("BEGIN IMMEDIATE")
        _validate(connection)
        yield connection
        connection.commit()
    except (OSError, sqlite3.Error, KeyError, TypeError, ValueError) as exc:
        raise AuthorityError("Authority storage is unavailable or malformed") from exc
    finally:
        if connection is not None:
            connection.close()  # Uncommitted work rolls back; committed reservations remain.


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError("Duplicate authority packet key")
        result[key] = value
    return result


def register_packet(path, packet_path, *, expected_sha256=None):
    """Owner/operator enrollment of exact raw packet bytes, never normalized JSON."""
    if expected_sha256 is not None:
        _hash(expected_sha256, "owner-reviewed packet SHA-256")
    try:
        with open(packet_path, "rb") as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise AuthorityError("Authority packet is too large")
        packet = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        raise AuthorityError("Authority packet is unavailable or malformed") from exc
    if not isinstance(packet, dict):
        raise AuthorityError("Authority packet must be an object")
    operation = _require(packet.get("operation_id"), _OPERATION, "operation identity")
    if type(packet.get("repair_attempt_limit")) is not int or packet["repair_attempt_limit"] != 2:
        raise AuthorityError("Authority packet must allow exactly two total attempts")
    command = _hash(packet.get("approved_command_sha256"), "command SHA-256")
    evidence = packet.get("retry_evidence_sha256")
    if "retry_evidence_sha256" in packet:
        _hash(evidence, "retry evidence SHA-256")
    packet_hash = hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and packet_hash != expected_sha256:
        raise AuthorityError("Authority packet bytes differ from the owner-reviewed SHA-256")
    with _transaction(path) as connection:
        connection.execute("INSERT INTO operations VALUES(?,2,?) ON CONFLICT(operation_id) DO NOTHING",
                           (operation, _utc()))
        connection.execute("INSERT INTO approvals VALUES(?,?,?,?,?) ON CONFLICT(packet_sha256) DO NOTHING",
                           (packet_hash, operation, command, evidence, _utc()))
        enrolled = _approval(connection, operation, packet_hash, command)
        if enrolled["retry_evidence_sha256"] != evidence:
            raise AuthorityError("Authority enrollment conflict")
    return {"operation_id": operation, "packet_sha256": packet_hash,
            "command_sha256": command, "retry_evidence_sha256": evidence}


def _approval(connection, operation_id, packet_sha256, command_sha256):
    _require(operation_id, _OPERATION, "operation identity")
    _hash(packet_sha256, "packet SHA-256")
    _hash(command_sha256, "command SHA-256")
    row = connection.execute(
        "SELECT * FROM approvals WHERE operation_id=? AND packet_sha256=? AND command_sha256=?",
        (operation_id, packet_sha256, command_sha256)).fetchone()
    if row is None:
        raise AuthorityError("Exact packet and command have not been owner-enrolled")
    return row


def check_approval(path, operation_id, packet_sha256, command_sha256):
    """Check enrollment; this does not reserve a slot or authorize dispatch."""
    with _transaction(path) as connection:
        _approval(connection, operation_id, packet_sha256, command_sha256)


def reserve(path, operation_id, packet_sha256, command_sha256, invocation_id,
            retry_evidence_sha256=None):
    """Atomically consume a slot before execution; replay never returns a slot."""
    _require(invocation_id, _INVOCATION, "invocation identity")
    _evidence(retry_evidence_sha256)
    with _transaction(path) as connection:
        approval = _approval(connection, operation_id, packet_sha256, command_sha256)
        if approval["retry_evidence_sha256"] != retry_evidence_sha256:
            raise AuthorityError("Retry evidence does not match the registered packet")
        if connection.execute("SELECT 1 FROM attempts WHERE invocation_id=?", (invocation_id,)).fetchone():
            raise AuthorityError("Invocation was already reserved")
        history = connection.execute(
            "SELECT a.*,o.outcome FROM attempts a LEFT JOIN outcomes o USING(attempt_id) "
            "WHERE a.operation_id=? ORDER BY a.attempt_number", (operation_id,)).fetchall()
        if len(history) >= 2:
            raise AuthorityError("Two-total-attempt budget is exhausted")
        if history:
            if history[0]["outcome"] != "FAILED":
                raise AuthorityError("Prior attempt succeeded, is unresolved, or has unknown outcome")
            if not retry_evidence_sha256 or packet_sha256 == history[0]["packet_sha256"]:
                raise AuthorityError("Retry needs a separately registered reassessment packet")
        attempt_id = uuid.uuid4().hex
        attempt_number = len(history) + 1
        connection.execute("INSERT INTO attempts VALUES(?,?,?,?,?,?,?,?)",
                           (attempt_id, operation_id, packet_sha256, command_sha256,
                            invocation_id, attempt_number, retry_evidence_sha256, _utc()))
    return {"attempt_id": attempt_id, "attempt_number": attempt_number}


def finish(path, attempt_id, outcome):
    """Append one durable outcome; UNKNOWN is permanent and consumes its slot."""
    _require(attempt_id, _ATTEMPT, "attempt identity")
    if not isinstance(outcome, str) or outcome not in _OUTCOMES:
        raise AuthorityError("Invalid attempt outcome")
    with _transaction(path) as connection:
        if not connection.execute("SELECT 1 FROM attempts WHERE attempt_id=?", (attempt_id,)).fetchone():
            raise AuthorityError("Attempt does not exist")
        prior = connection.execute("SELECT outcome FROM outcomes WHERE attempt_id=?", (attempt_id,)).fetchone()
        if prior is not None:
            if prior[0] != outcome:
                raise AuthorityError("Attempt outcome cannot be changed")
            return
        connection.execute("INSERT INTO outcomes VALUES(?,?,?)", (attempt_id, outcome, _utc()))
