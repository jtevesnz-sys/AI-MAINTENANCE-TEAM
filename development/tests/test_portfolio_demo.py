"""Exercise the standalone portfolio example as a visitor would."""
import os
import importlib.util
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


class PortfolioDemoTest(unittest.TestCase):
    def test_demo_shows_failed_repair_retry_and_attempt_limit(self):
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run(
            [sys.executable, "examples/maintenance_demo.py"], cwd=root,
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for expected in ("SIMULATED", "Attempt 1: FAILED", "Attempt 2: FAILED",
                         "Attempt 3: BLOCKED", "No real repair was run"):
            self.assertIn(expected, result.stdout)

    def test_unrelated_denial_is_not_reported_as_attempt_limit(self):
        root = Path(__file__).resolve().parents[2]
        spec = importlib.util.spec_from_file_location("portfolio_demo", root / "examples" / "maintenance_demo.py")
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        real_reserve = demo.authority.reserve
        calls = 0

        def reserve_with_storage_failure(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 3:
                raise demo.authority.AuthorityError("Authority storage is unavailable")
            return real_reserve(*args, **kwargs)

        output = io.StringIO()
        with patch.object(demo.authority, "reserve", side_effect=reserve_with_storage_failure):
            with contextlib.redirect_stdout(output):
                with self.assertRaises(demo.authority.AuthorityError):
                    demo.main()
        self.assertNotIn("Attempt 3: BLOCKED by the two-attempt ledger", output.getvalue())


if __name__ == "__main__":
    unittest.main()
