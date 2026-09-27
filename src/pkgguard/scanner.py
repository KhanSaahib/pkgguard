"""Walks an extracted package directory and applies the ruleset."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .rules import (
    Finding,
    Severity,
    scan_js_source,
    scan_lifecycle_scripts,
    scan_py_source,
    scan_setup_py,
)

JS_EXTENSIONS = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")
PY_EXTENSIONS = (".py", ".pyw")

# Files above this size are not pattern-scanned (regexes over huge minified
# bundles are slow and noisy), but they are always *reported* as an INFO
# finding so that padding a payload past the limit can't hide it silently.
MAX_FILE_BYTES = 10 * 1024 * 1024

# Only VCS metadata and bytecode caches are skipped. Directories such as
# dist/, build/, lib/ and test/ are scanned: they ship inside published
# packages and a lifecycle script can execute code from any of them.
SKIP_DIR_NAMES = {".git", ".hg", ".svn", "__pycache__"}


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
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if counts[level]:
                return level
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
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _iter_source_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIR_NAMES)
        for name in sorted(filenames):
            yield Path(dirpath) / name


def _scanner_for(path: Path):
    if path.name == "setup.py":
        return scan_setup_py
    if path.suffix in PY_EXTENSIONS:
        return scan_py_source
    if path.suffix in JS_EXTENSIONS:
        return scan_js_source
    return None


def _too_large(path: Path, label: str) -> Finding | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= MAX_FILE_BYTES:
        return None
    return Finding(
        "LARGE_FILE_NOT_SCANNED", Severity.INFO, label, 1,
        f"File is {size:,} bytes, above the {MAX_FILE_BYTES:,}-byte scan limit; "
        "review it manually",
    )


def scan_directory(root_path: str) -> ScanReport:
    root = Path(root_path)
    report = ScanReport(target=str(root))

    package_json = root / "package.json"
    if package_json.is_file():
        skipped = _too_large(package_json, "package.json")
        text = None if skipped else _read_text(package_json)
        if skipped:
            report.findings.append(skipped)
        if text:
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {}
            if isinstance(data, dict):
                report.findings.extend(
                    scan_lifecycle_scripts(data.get("scripts", {}), "package.json")
                )

    for path in _iter_source_files(root):
        scan = _scanner_for(path)
        if scan is None:
            continue
        rel = str(path.relative_to(root))
        skipped = _too_large(path, rel)
        if skipped:
            report.findings.append(skipped)
            continue
        text = _read_text(path)
        if text:
            report.findings.extend(scan(text, rel))

    report.findings.sort(key=lambda f: -f.severity.value)
    return report
