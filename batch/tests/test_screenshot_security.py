"""Regression tests for screenshot serving without vulnerable StaticFiles."""
import asyncio
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as backend
from fastapi import HTTPException
from fastapi.responses import FileResponse


class ScreenshotSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        patcher = patch.object(backend, "SCREENSHOTS_DIR", self.temp_dir.name)
        patcher.start()
        self.addCleanup(patcher.stop)

    def get(self, filename):
        return asyncio.run(backend.get_screenshot(filename))

    def test_existing_png_is_served(self):
        file_path = Path(self.temp_dir.name) / "Account_1_step5_123.png"
        file_path.write_bytes(b"\\x89PNG\\r\\n\\x1a\\n")
        response = self.get(file_path.name)
        self.assertIsInstance(response, FileResponse)
        self.assertEqual(response.media_type, "image/png")
        self.assertEqual(response.path, str(file_path))

    def test_unicode_account_ids_remain_supported(self):
        filename = "中文账号_step5_123.png"
        (Path(self.temp_dir.name) / filename).write_bytes(b"sample")
        self.assertIsInstance(self.get(filename), FileResponse)

    def test_rejects_unc_traversal_alt_stream_and_non_png(self):
        unsafe = [
            "../secret.png", r"..\\secret.png", r"\\\\remote.invalid\\share.png",
            "photo.png:stream", "/etc/passwd.png", "photo.txt",
            ".hidden.png", "hello\\x00.png", "hello\\n.png",
        ]
        for filename in unsafe:
            with self.subTest(filename=repr(filename)):
                with self.assertRaises(HTTPException) as cm:
                    self.get(filename)
                self.assertEqual(cm.exception.status_code, 404)

    def test_missing_file_404(self):
        with self.assertRaises(HTTPException) as cm:
            self.get("missing.png")
        self.assertEqual(cm.exception.status_code, 404)

    def test_symlink_is_not_served(self):
        target = Path(self.temp_dir.name) / "target.png"
        target.write_bytes(b"sample")
        link = Path(self.temp_dir.name) / "link.png"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("Creating symlinks is not permitted in this environment")
        with self.assertRaises(HTTPException) as cm:
            self.get(link.name)
        self.assertEqual(cm.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
