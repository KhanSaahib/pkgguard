from __future__ import annotations

import argparse
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from . import __version__
from .extract import UnsafeArchiveError, extract_package
from .report import render_text
from .scanner import ScanReport, scan_directory

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
ARCHIVE_SUFFIXES = (".tgz", ".tar.gz", ".tar", ".whl", ".zip")

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class _TargetError(Exception):
    pass


def _scan_path(path: str) -> ScanReport:
    p = Path(path)
    if p.is_dir():
        return scan_directory(str(p))
    if p.is_file() and str(p).lower().endswith(ARCHIVE_SUFFIXES):
        with tempfile.TemporaryDirectory(prefix="pkgguard-") as tmp:
            try:
                pkg_root = extract_package(str(p), tmp)
            except (UnsafeArchiveError, tarfile.TarError, zipfile.BadZipFile, OSError) as exc:
                raise _TargetError(f"refusing to extract {path}: {exc}") from exc
            report = scan_directory(pkg_root)
            report.target = str(p)
            return report
    raise _TargetError(
        f"unsupported target: {path} "
        f"(expected a directory or one of {', '.join(ARCHIVE_SUFFIXES)})"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkgguard",
        description=(
            "Statically scan npm/PyPI package contents for malicious "
            "install-time behavior, without executing any package code."
        ),
        epilog="exit codes: 0 = below threshold, 1 = findings at/above --fail-on, 2 = error",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="scan a package directory or archive")
    scan_p.add_argument("path", help="directory, .tgz/.tar.gz/.tar (npm, sdist), or .whl/.zip (wheel)")
    scan_p.add_argument("--json", action="store_true", help="emit a JSON report on stdout")
    scan_p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="critical",
        help="exit 1 if a finding at or above this severity is present (default: critical)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "scan":
        try:
            report = _scan_path(args.path)
        except _TargetError as exc:
            print(f"pkgguard: {exc}", file=sys.stderr)
            return EXIT_ERROR

        print(report.to_json() if args.json else render_text(report))

        threshold = SEVERITY_RANK[args.fail_on.upper()]
        if SEVERITY_RANK[report.verdict] >= threshold:
            return EXIT_FINDINGS
        return EXIT_OK

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
