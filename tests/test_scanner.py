import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pkgguard.scanner import scan_directory

FIXTURES = Path(__file__).parent / "fixtures"


class TestBenignNpmPackage(unittest.TestCase):
    def test_no_findings(self):
        report = scan_directory(str(FIXTURES / "benign_npm_pkg"))
        self.assertEqual(report.verdict, "CLEAN")
        self.assertEqual(report.findings, [])


class TestMaliciousNpmPackage(unittest.TestCase):
    def setUp(self):
        self.report = scan_directory(str(FIXTURES / "malicious_npm_pkg"))

    def test_verdict_critical(self):
        self.assertEqual(self.report.verdict, "CRITICAL")

    def test_detects_remote_exec_lifecycle_script(self):
        ids = {f.rule_id for f in self.report.findings}
        self.assertIn("LIFECYCLE_REMOTE_EXEC", ids)

    def test_detects_secret_exfil_chain(self):
        ids = {f.rule_id for f in self.report.findings}
        self.assertIn("SECRET_EXFIL_CHAIN", ids)

    def test_detects_worm_sibling_write(self):
        ids = {f.rule_id for f in self.report.findings}
        self.assertIn("WORM_SIBLING_WRITE", ids)


class TestBenignPypiPackage(unittest.TestCase):
    def test_no_findings(self):
        report = scan_directory(str(FIXTURES / "benign_pypi_pkg"))
        self.assertEqual(report.verdict, "CLEAN")


class TestMaliciousPypiPackage(unittest.TestCase):
    def setUp(self):
        self.report = scan_directory(str(FIXTURES / "malicious_pypi_pkg"))

    def test_verdict_critical(self):
        self.assertEqual(self.report.verdict, "CRITICAL")

    def test_detects_shell_true(self):
        ids = {f.rule_id for f in self.report.findings}
        self.assertIn("SHELL_EXEC_SHELL_TRUE", ids)

    def test_detects_secret_exfil_chain(self):
        ids = {f.rule_id for f in self.report.findings}
        self.assertIn("SECRET_EXFIL_CHAIN", ids)


if __name__ == "__main__":
    unittest.main()
