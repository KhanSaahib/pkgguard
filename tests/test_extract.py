import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pkgguard.extract import UnsafeArchiveError, extract_package, safe_extract_tar


class TestPathTraversalGuard(unittest.TestCase):
    def test_rejects_zip_slip_style_member(self):
        with tempfile.TemporaryDirectory() as work:
            work_path = Path(work)
            evil_tar = work_path / "evil.tar.gz"
            escape_target = work_path / "escaped.txt"

            with tarfile.open(evil_tar, "w:gz") as tf:
                info = tarfile.TarInfo(name="../escaped.txt")
                data = b"pwned"
                info.size = len(data)
                import io

                tf.addfile(info, io.BytesIO(data))

            dest = work_path / "dest"
            dest.mkdir()
            with self.assertRaises(UnsafeArchiveError):
                safe_extract_tar(str(evil_tar), str(dest))
            self.assertFalse(escape_target.exists())

    def test_extracts_normal_tarball(self):
        with tempfile.TemporaryDirectory() as work:
            work_path = Path(work)
            good_tar = work_path / "good.tar.gz"
            with tarfile.open(good_tar, "w:gz") as tf:
                import io

                info = tarfile.TarInfo(name="package/index.js")
                data = b"module.exports = {};"
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

            dest = work_path / "dest"
            root = extract_package(str(good_tar), str(dest))
            self.assertTrue((Path(root) / "index.js").exists())


if __name__ == "__main__":
    unittest.main()
