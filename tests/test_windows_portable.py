import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile, ZipInfo

from tools import build_windows_portable as portable


class PortableBuilderTests(unittest.TestCase):
    def test_asset_digest_checked_before_inputs_are_returned(self):
        with tempfile.TemporaryDirectory() as folder:
            cache = Path(folder)
            asset = cache / "locked.zip"
            asset.write_bytes(b"approved")
            digest = hashlib.sha256(b"approved").hexdigest()
            with patch.object(portable, "ASSET_SHA256", {asset.name: digest}):
                self.assertEqual(portable.verified_assets(cache), {asset.name: asset})
                asset.write_bytes(b"tampered")
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    portable.verified_assets(cache)

    def test_archive_rejects_parent_paths_and_windows_streams(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("../escaped", "app/file:stream", "/absolute", "app\\payload"):
                archive = root / "input.zip"
                with ZipFile(archive, "w") as data:
                    item = ZipInfo(name)
                    item.filename = name
                    data.writestr(item, b"illegal")
                with ZipFile(archive) as data, self.assertRaisesRegex(ValueError, "Unsafe archive"):
                    portable.extract_checked(data, root / "stage")
                self.assertFalse((root / "escaped").exists())

    def test_release_zip_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            stage = root / "stage"
            stage.mkdir()
            (stage / "WiFiScope.cmd").write_bytes(b"launcher")
            output = root / "out.zip"
            portable.write_archive(stage, output)
            with ZipFile(output) as data:
                self.assertEqual(data.namelist(), ["WiFiScope.cmd"])
            before = output.read_bytes()
            with self.assertRaises(FileExistsError):
                portable.write_archive(stage, output)
            self.assertEqual(output.read_bytes(), before)
