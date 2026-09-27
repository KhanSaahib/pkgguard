"""Safe extraction of npm tarballs / PyPI sdists & wheels.

Package archives are, by definition, untrusted input for this tool - the
whole point of pkgguard is to inspect packages *before* they are trusted
enough to install. This module therefore never calls ``extractall()`` on an
archive. Instead it walks every member itself and:

* rejects any member whose path would land outside the extraction root
  (``../`` traversal, absolute paths, Windows drive paths - "Zip Slip" /
  CVE-2007-4559-style bugs);
* rejects symlinks and hardlinks whose *target* points outside the root,
  and never materializes links at all, so a link planted by one member
  cannot be used by a later member to write outside the root;
* rejects device files and FIFOs;
* enforces an upper bound on member count and total uncompressed size so a
  decompression bomb cannot exhaust disk space.

Only regular files and directories are written, with default permissions
(no setuid/exec bits are restored). None of this depends on the Python
version's ``tarfile`` extraction-filter defaults.
"""
from __future__ import annotations

import os
import shutil
import tarfile
import zipfile
from pathlib import Path

MAX_MEMBERS = 20_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024  # 512 MiB uncompressed


class UnsafeArchiveError(Exception):
    """The archive would write outside its root or is otherwise unsafe to unpack."""


def _root(dest_dir: str) -> str:
    return os.path.realpath(dest_dir)


def _is_within(root: str, candidate: str) -> bool:
    try:
        return os.path.commonpath([root, candidate]) == root
    except ValueError:  # different drives on Windows
        return False


def _checked_target(root: str, name: str) -> str:
    """Resolve a member name lexically against ``root`` and reject escapes.

    Lexical resolution is sufficient here because this module never creates
    symlinks, so no path component on disk can redirect the write.
    """
    if not name or name.startswith(("/", "\\")) or os.path.isabs(name):
        raise UnsafeArchiveError(f"archive member has an absolute path: {name}")
    target = os.path.normpath(os.path.join(root, name))
    if not _is_within(root, target):
        raise UnsafeArchiveError(f"archive member escapes extraction directory: {name}")
    return target


def _check_link(root: str, member: tarfile.TarInfo) -> None:
    link = member.linkname
    if not link or link.startswith(("/", "\\")) or os.path.isabs(link):
        raise UnsafeArchiveError(f"archive contains an absolute link: {member.name} -> {link}")
    # Symlink targets are relative to the link's own directory; hardlink
    # targets are relative to the archive root.
    base = os.path.dirname(os.path.join(root, member.name)) if member.issym() else root
    target = os.path.normpath(os.path.join(base, link))
    if not _is_within(root, target):
        raise UnsafeArchiveError(
            f"archive contains a link pointing outside the extraction directory: "
            f"{member.name} -> {link}"
        )


def _account(total: int, size: int, count: int) -> int:
    if count > MAX_MEMBERS:
        raise UnsafeArchiveError(f"archive has more than {MAX_MEMBERS} members")
    total += max(size, 0)
    if total > MAX_TOTAL_BYTES:
        raise UnsafeArchiveError(
            f"archive expands to more than {MAX_TOTAL_BYTES // (1024 * 1024)} MiB"
        )
    return total


def safe_extract_tar(archive_path: str, dest_dir: str) -> None:
    root = _root(dest_dir)
    total = 0
    with tarfile.open(archive_path, "r:*") as tf:
        # Validate the whole archive before writing anything to disk.
        members = tf.getmembers()
        for count, member in enumerate(members, start=1):
            _checked_target(root, member.name)
            if member.issym() or member.islnk():
                _check_link(root, member)
            elif not (member.isfile() or member.isdir()):
                raise UnsafeArchiveError(
                    f"archive contains a device file or FIFO: {member.name}"
                )
            total = _account(total, member.size if member.isfile() else 0, count)

        for member in members:
            target = _checked_target(root, member.name)
            if member.isdir():
                os.makedirs(target, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tf.extractfile(member)
                if src is None:
                    continue
                with src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
            # In-tree links are validated above but intentionally not
            # created: the scanner reads the real file they point to anyway.


def safe_extract_zip(archive_path: str, dest_dir: str) -> None:
    root = _root(dest_dir)
    total = 0
    with zipfile.ZipFile(archive_path) as zf:
        infos = zf.infolist()
        for count, info in enumerate(infos, start=1):
            _checked_target(root, info.filename)
            total = _account(total, info.file_size, count)

        for info in infos:
            target = _checked_target(root, info.filename)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)


def extract_package(archive_path: str, dest_dir: str) -> str:
    """Extract a .tgz/.tar.gz/.tar/.whl/.zip package into ``dest_dir``.

    Returns the effective package root, unwrapping the common single
    top-level directory (e.g. npm's ``package/``).
    """
    lower = archive_path.lower()
    os.makedirs(dest_dir, exist_ok=True)
    if lower.endswith((".tgz", ".tar.gz", ".tar")):
        safe_extract_tar(archive_path, dest_dir)
    elif lower.endswith((".whl", ".zip")):
        safe_extract_zip(archive_path, dest_dir)
    else:
        raise ValueError(f"unsupported archive type: {archive_path}")

    entries = list(Path(dest_dir).iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return str(entries[0])
    return dest_dir
