import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

sys.path.insert(0, str(ROOT / "src"))

import pkgguard


def run_cli(*args):
    # Inherit the parent environment: on Windows an empty env drops
    # SYSTEMROOT and friends, which breaks interpreter start-up.
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(
        [sys.executable, "-m", "pkgguard", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


class TestCli(unittest.TestCase):
    def test_benign_exits_zero(self):
        result = run_cli("scan", str(FIXTURES / "benign_npm_pkg"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("CLEAN", result.stdout)

    def test_clean_report_says_no_findings(self):
        result = run_cli("scan", str(FIXTURES / "benign_npm_pkg"))
        self.assertIn("summary: no findings", result.stdout)

    def test_malicious_exits_nonzero(self):
        result = run_cli("scan", str(FIXTURES / "malicious_npm_pkg"))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("CRITICAL", result.stdout)

    def test_fail_on_threshold(self):
        # The malicious PyPI fixture has CRITICAL findings, so even the
        # strictest threshold must fail; a CLEAN package never fails.
        self.assertEqual(run_cli("scan", "--fail-on", "low", str(FIXTURES / "benign_pypi_pkg")).returncode, 0)
        self.assertEqual(run_cli("scan", "--fail-on", "low", str(FIXTURES / "malicious_pypi_pkg")).returncode, 1)

    def test_json_output_is_valid(self):
        result = run_cli("scan", "--json", str(FIXTURES / "malicious_pypi_pkg"))
        data = json.loads(result.stdout)
        self.assertEqual(data["verdict"], "CRITICAL")
        self.assertTrue(any(f["rule_id"] == "SECRET_EXFIL_CHAIN" for f in data["findings"]))

    def test_version_flag(self):
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(pkgguard.__version__, result.stdout)

    def test_unsupported_target_exits_two(self):
        result = run_cli("scan", str(ROOT / "does-not-exist.bin"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsupported target", result.stderr)

    def test_unsafe_archive_exits_two_without_traceback(self):
        with tempfile.TemporaryDirectory() as work:
            evil = Path(work) / "evil.tgz"
            with tarfile.open(evil, "w:gz") as tf:
                info = tarfile.TarInfo(name="../escaped.txt")
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
            result = run_cli("scan", str(evil))
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing to extract", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
