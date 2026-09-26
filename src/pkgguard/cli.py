from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

from .extract import extract_package
from .report import render_text
from .scanner import ScanReport, scan_directory

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".tar", ".whl", ".zip")


def _scan_path(path: str) -> ScanReport:
    p = Path(path)
    if p.is_dir():
        return scan_directory(str(p))
    if p.is_file() and str(p).lower().endswith(ARCHIVE_SUFFIXES):
        with tempfile.TemporaryDirectory(prefix="pkgguard-") as tmp:
            pkg_root = extract_package(str(p), tmp)
            report = scan_directory(pkg_root)
            report.target = str(p)
            return report
    raise SystemExit(f"pkgguard: unsupported target: {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pkgguard")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a package directory or archive")
    scan_p.add_argument("path", help="directory, .tgz/.tar.gz (npm), or .whl/.zip (pypi)")
    scan_p.add_argument("--json", action="store_true", help="emit JSON report")
    scan_p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="critical",
        help="exit non-zero if a finding at or above this severity is present",
    )

    args = parser.parse_args(argv)

    if args.command == "scan":
        report = _scan_path(args.path)
        if args.json:
            print(report.to_json())
        else:
            print(render_text(report))

        threshold = SEVERITY_RANK[args.fail_on.upper()]
        if SEVERITY_RANK[report.verdict] >= threshold:
            return 1
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
