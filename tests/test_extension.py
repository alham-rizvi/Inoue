import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "extension"


class ExtensionReleaseTests(unittest.TestCase):
    def test_manifest_supports_chrome_and_firefox(self):
        manifest = json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["background"]["service_worker"], "background.js")
        self.assertIn("storage", manifest["permissions"])
        self.assertIn("http://*/*", manifest["optional_host_permissions"])
        self.assertIn("gecko", manifest["browser_specific_settings"])
        self.assertIn("http://127.0.0.1:8000/*", manifest["host_permissions"])

    def test_extension_uses_fast_read_only_scan_and_does_not_bundle_keys(self):
        background = (EXTENSION / "background.js").read_text(encoding="utf-8")
        popup = (EXTENSION / "popup.js").read_text(encoding="utf-8")

        self.assertIn('modules: ["fast"]', background)
        self.assertIn('"X-API-Key"', background)
        self.assertIn("technology.name", popup)
        self.assertIn("confidence_score", popup)
        self.assertIn("requestApiPermission", popup)
        self.assertNotIn("test-key-not-real", background)
        self.assertNotIn("INOUE_API_KEY=", background)

    def test_release_builder_exists_and_uses_zip_archives(self):
        builder = (ROOT / "scripts" / "build_extension.py").read_text(encoding="utf-8")

        self.assertIn("zipfile.ZipFile", builder)
        self.assertIn("chrome", builder)
        self.assertIn("firefox", builder)


if __name__ == "__main__":
    unittest.main()
