"""Walks an extracted package directory and applies the ruleset."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .rules import Finding, Severity, scan_js_source, scan_lifecycle_scripts, scan_py_source, scan_setup_py

JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts")
MAX_FILE_BYTES = 2_000_000  # skip huge bundled/minified blobs, not worth the noise
SKIP_DIR_NAMES = {".git", "__pycache__", "test", "tests", "dist", ".idea"}


@dataclass
class ScanReport:
    target: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    @property
    def verdict(self) -> str:
        counts = self.severity_counts
        if counts["CRITICAL"]:
            return "CRITICAL"
        if counts["HIGH"]:
            return "HIGH"
        if counts["MEDIUM"]:
            return "MEDIUM"
        if counts["LOW"]:
            return "LOW"
        return "CLEAN"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "verdict": self.verdict,
            "severity_counts": self.severity_counts,
            "findings": [
                {**asdict(f), "severity": f.severity.name} for f in self.findings
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            yield Path(dirpath) / name


def scan_directory(root_path: str) -> ScanReport:
    root = Path(root_path)
    report = ScanReport(target=str(root))

    package_json = root / "package.json"
    if package_json.is_file():
        text = _read_text(package_json)
        if text:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            report.findings.extend(
                scan_lifecycle_scripts(data.get("scripts", {}), str(package_json))
            )

    for path in _iter_source_files(root):
        rel = str(path.relative_to(root))
        if path.name == "setup.py":
            text = _read_text(path)
            if text:
                report.findings.extend(scan_setup_py(text, rel))
        elif path.suffix == ".py":
            text = _read_text(path)
            if text:
                report.findings.extend(scan_py_source(text, rel))
        elif path.suffix in JS_EXTENSIONS:
            text = _read_text(path)
            if text:
                report.findings.extend(scan_js_source(text, rel))

    report.findings.sort(key=lambda f: -f.severity.value)
    return report
