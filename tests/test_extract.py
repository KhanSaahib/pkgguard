import io
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pkgguard import extract
from pkgguard.extract import (
    UnsafeArchiveError,
    extract_package,
    safe_extract_tar,
    safe_extract_zip,
)


def _add_file(tf: tarfile.TarFile, name: str, data: bytes = b"x") -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def _add_link(tf: tarfile.TarFile, name: str, target: str, kind=tarfile.SYMTYPE) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = kind
    info.linkname = target
    tf.addfile(info)


class _ArchiveTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.work = Path(self._tmp.name)
        self.dest = self.work / "dest"
        self.dest.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def make_tar(self, build) -> str:
        path = self.work / "pkg.tar.gz"
        with tarfile.open(path, "w:gz") as tf:
            build(tf)
        return str(path)

    def assert_nothing_escaped(self):
        outside = [p for p in self.work.iterdir() if p.name not in {"dest", "pkg.tar.gz", "pkg.zip"}]
        self.assertEqual(outside, [], f"files written outside dest: {outside}")


class TestTarPathTraversal(_ArchiveTestCase):
    def test_rejects_dotdot_member(self):
        tar = self.make_tar(lambda tf: _add_file(tf, "../escaped.txt", b"pwned"))
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_tar(tar, str(self.dest))
        self.assert_nothing_escaped()

    def test_rejects_absolute_member(self):
        abs_name = str((self.work / "abs_escape.txt").resolve()).replace("\\", "/")
        tar = self.make_tar(lambda tf: _add_file(tf, abs_name, b"pwned"))
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_tar(tar, str(self.dest))
        self.assert_nothing_escaped()

    def test_extracts_normal_tarball(self):
        tar = self.make_tar(lambda tf: _add_file(tf, "package/index.js", b"module.exports = {};"))
        root = extract_package(tar, str(self.dest))
        self.assertTrue((Path(root) / "index.js").exists())


class TestTarLinks(_ArchiveTestCase):
    def test_rejects_symlink_pointing_outside(self):
        # Link *name* is inside dest, link *target* is not: the case the
        # original implementation checked the wrong field for.
        tar = self.make_tar(lambda tf: _add_link(tf, "package/evil", "../../outside"))
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_tar(tar, str(self.dest))

    def test_rejects_absolute_symlink(self):
        tar = self.make_tar(lambda tf: _add_link(tf, "package/evil", "/etc/passwd"))
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_tar(tar, str(self.dest))

    def test_rejects_hardlink_pointing_outside(self):
        tar = self.make_tar(
            lambda tf: _add_link(tf, "package/evil", "../outside", kind=tarfile.LNKTYPE)
        )
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_tar(tar, str(self.dest))

    def test_write_through_symlink_cannot_escape(self):
        # Classic two-step attack: plant a symlink to a directory outside
        # the root, then write a regular file "through" it.
        def build(tf):
            _add_link(tf, "package/dir", "..")
            _add_link(tf, "package/dir/up", "..")
            _add_file(tf, "package/dir/up/escaped.txt", b"pwned")

        tar = self.make_tar(build)
        try:
            safe_extract_tar(tar, str(self.dest))
        except UnsafeArchiveError:
            pass
        self.assert_nothing_escaped()
        for p in self.dest.rglob("*"):
            self.assertFalse(p.is_symlink(), f"symlink materialized: {p}")

    def test_in_tree_symlinks_are_not_materialized(self):
        def build(tf):
            _add_file(tf, "package/real.js", b"1;")
            _add_link(tf, "package/alias.js", "real.js")

        root = extract_package(self.make_tar(build), str(self.dest))
        self.assertTrue((Path(root) / "real.js").is_file())
        self.assertFalse((Path(root) / "alias.js").exists())

    def test_rejects_device_file(self):
        def build(tf):
            info = tarfile.TarInfo(name="package/dev")
            info.type = tarfile.CHRTYPE
            tf.addfile(info)

        with self.assertRaises(UnsafeArchiveError):
            safe_extract_tar(self.make_tar(build), str(self.dest))


class TestArchiveLimits(_ArchiveTestCase):
    def test_rejects_archive_over_total_size_limit(self):
        tar = self.make_tar(lambda tf: _add_file(tf, "package/big.js", b"a" * 2048))
        with mock.patch.object(extract, "MAX_TOTAL_BYTES", 1024):
            with self.assertRaises(UnsafeArchiveError):
                safe_extract_tar(tar, str(self.dest))

    def test_rejects_archive_over_member_limit(self):
        def build(tf):
            for i in range(5):
                _add_file(tf, f"package/f{i}.js")

        with mock.patch.object(extract, "MAX_MEMBERS", 3):
            with self.assertRaises(UnsafeArchiveError):
                safe_extract_tar(self.make_tar(build), str(self.dest))


class TestZip(_ArchiveTestCase):
    def make_zip(self, entries: dict) -> str:
        path = self.work / "pkg.zip"
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return str(path)

    def test_rejects_zip_slip(self):
        z = self.make_zip({"../escaped.txt": b"pwned"})
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_zip(z, str(self.dest))
        self.assert_nothing_escaped()

    def test_extracts_normal_wheel(self):
        z = self.make_zip({"demo/__init__.py": b"", "demo-1.0.dist-info/METADATA": b"Name: demo"})
        extract_package(z, str(self.dest))
        self.assertTrue((self.dest / "demo" / "__init__.py").is_file())

    def test_rejects_zip_over_total_size_limit(self):
        z = self.make_zip({"demo/big.py": b"a" * 2048})
        with mock.patch.object(extract, "MAX_TOTAL_BYTES", 1024):
            with self.assertRaises(UnsafeArchiveError):
                safe_extract_zip(z, str(self.dest))


if __name__ == "__main__":
    unittest.main()
