# Source and scope

- The authority ledger was copied from `development/maintenance_authority.py`
  in the local `MAINTENANCE-BLINK` checkout at commit `abb9a29`.
- `development/tests/test_maintenance_authority.py` was copied from that same
  checkout. It tests the real ledger with temporary synthetic inputs.
- `examples/maintenance_demo.py` and its visitor test started as material from
  the previous work session and were copied from that checkout's working tree.
  The demo and test were then extended here to distinguish the attempt-limit
  denial from unrelated ledger failures.
- This repository contains a narrow, self-contained example. The broader
  Maintenance/BLINK runtime, its integrations, original package, deployment
  configuration, and private operational records are not included.
- The source checkout's license and public distribution permissions have not
  been established. No open-source license is asserted here.
