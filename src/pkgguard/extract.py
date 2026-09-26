"""Safe extraction of npm tarballs / PyPI sdists & wheels.

Package archives are, by definition, untrusted input for this tool - the
whole point of pkgguard is to inspect packages before they are trusted
enough to install. Naive use of tarfile.extractall()/zipfile.extractall()
is vulnerable to path traversal (members whose name climbs out of the
target directory via '../' or an absolute path, aka "Zip Slip" /
CVE-2007-4559-style bugs) and to malicious symlinks pointing outside the
extraction root. This module resolves every member path and rejects
anything that would land outside the destination before writing it.
"""
from __future__ import annotations

import os
import tarfile
import zipfile
from pathlib import Path


class UnsafeArchiveError(Exception):
    pass


def _is_within_directory(directory: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(directory.resolve())
        return True
    except ValueError:
        return False


def safe_extract_tar(archive_path: str, dest_dir: str) -> None:
    dest = Path(dest_dir)
    with tarfile.open(archive_path, "r:*") as tf:
        for member in tf.getmembers():
            member_path = dest / member.name
            if not _is_within_directory(dest, member_path):
                raise UnsafeArchiveError(
                    f"archive member escapes extraction directory: {member.name}"
                )
            if member.issym() or member.islnk():
                link_target = dest / member.name
                if not _is_within_directory(dest, link_target):
                    raise UnsafeArchiveError(
                        f"archive contains unsafe link: {member.name}"
                    )
        tf.extractall(dest)  # noqa: S202 - membership already validated above


def safe_extract_zip(archive_path: str, dest_dir: str) -> None:
    dest = Path(dest_dir)
    with zipfile.ZipFile(archive_path) as zf:
        for name in zf.namelist():
            member_path = dest / name
            if not _is_within_directory(dest, member_path):
                raise UnsafeArchiveError(
                    f"archive member escapes extraction directory: {name}"
                )
        zf.extractall(dest)  # noqa: S202 - membership already validated above


def extract_package(archive_path: str, dest_dir: str) -> str:
    """Extract a .tgz/.tar.gz/.whl/.zip package into dest_dir, returning the
    effective package root (handles the common single-top-level-dir case)."""
    lower = archive_path.lower()
    os.makedirs(dest_dir, exist_ok=True)
    if lower.endswith((".tgz", ".tar.gz", ".tar")):
        safe_extract_tar(archive_path, dest_dir)
    elif lower.endswith((".whl", ".zip")):
        safe_extract_zip(archive_path, dest_dir)
    else:
        raise ValueError(f"unsupported archive type: {archive_path}")

    entries = [p for p in Path(dest_dir).iterdir()]
    if len(entries) == 1 and entries[0].is_dir():
        return str(entries[0])
    return dest_dir
