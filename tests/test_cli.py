import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "pkgguard", *args],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
    )


class TestCli(unittest.TestCase):
    def test_benign_exits_zero(self):
        result = run_cli("scan", str(FIXTURES / "benign_npm_pkg"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CLEAN", result.stdout)

    def test_malicious_exits_nonzero(self):
        result = run_cli("scan", str(FIXTURES / "malicious_npm_pkg"))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("CRITICAL", result.stdout)

    def test_json_output_is_valid(self):
        result = run_cli("scan", "--json", str(FIXTURES / "malicious_pypi_pkg"))
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "CRITICAL")
        self.assertTrue(any(f["rule_id"] == "SECRET_EXFIL_CHAIN" for f in data["findings"]))


if __name__ == "__main__":
    unittest.main()
