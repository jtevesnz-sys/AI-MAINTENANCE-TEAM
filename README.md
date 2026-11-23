# AI Maintenance Team

**A working demonstration of controlled maintenance attempts for AI-assisted systems.**

AI agents can help diagnose problems, but real repair actions need clear
authority, a record of what happened, and a safe response to uncertain outcomes.
This project demonstrates one part of that idea: a durable ledger for approved
repair attempts, built from the existing Maintenance/BLINK development work.

## Try the demonstration

Requires Python 3.11 or later. No third-party packages, API key or network
connection are required.

```bash
python examples/maintenance_demo.py
```

The script uses fictional data and a temporary SQLite database. It walks through
a proposed issue, a simulated owner approval, two simulated failed attempts and
the ledger rejecting a third. **It never launches a repair command.**

```text
SIMULATED maintenance: an imaginary service is unavailable
Janitor: record the issue and propose a repair for owner review
Owner: register a fictional approval for the demonstration
Technician: Attempt 1: FAILED (simulated)
Technician: Attempt 2: FAILED (simulated; evidence supplied)
Technician: Attempt 3: BLOCKED by the two-attempt ledger
No real repair was run. Temporary demonstration data was removed.
```

## What is implemented

The authority ledger in `development/maintenance_authority.py`:

- Binds a registered packet to an operation and a command hash.
- Reserves an attempt in SQLite before a caller could take an action.
- Rejects repeated invocation IDs and attempts beyond a two-attempt limit.
- Requires a separately registered reassessment packet and evidence for a retry
  following a recorded failure.
- Blocks retries following a success, an unknown outcome or an unresolved attempt.
- Keeps recorded outcomes immutable through the ledger interface.

Tests exercise concurrent reservations, replay, tampering, corrupted storage and
uncertain outcomes using isolated temporary files. The example uses this actual
ledger; Janitor, Technician, approval and failure events in the script are
**simulations**, not running AI agents or evidence of live operations.

## Test

```bash
python -m unittest discover -s development/tests -v
```

On Windows, symlink tests may be skipped when the account lacks permission to
create them. Some concurrent tests spawn child Python processes.

## Safety and scope

This is an **early portfolio prototype**, not a complete maintenance platform or
a production security product. The ledger does not authenticate a human owner,
verify that a repair actually occurred, execute repairs, enforce authorization on
its own, or make a system safe simply by being present. A deployment needs
independent identity and access controls, protected storage, a trusted dispatch
boundary, tested recovery, and a review of its operating environment. SQLite
does not protect against an administrator editing its files. An unknown outcome
means stop and investigate; it does not mean the action failed or was reversed.

## Project background

This small repository extracts a ledger and illustrative demo from the existing
Maintenance/BLINK project. See [PROVENANCE.md](PROVENANCE.md) for the exact
source references. This repository does not establish live deployment,
continuous monitoring or autonomous agent operation.

## Release status

Prepared for private development and review. Public release, license selection,
security review and independent validation remain outstanding.
