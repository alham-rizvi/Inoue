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

    def test_built_archive_includes_every_source_file_including_subdirectories(self):
        """Regression guard: an earlier version of build_extension.py only
        iterated the top level of extension/ (path.is_file() on
        SOURCE.iterdir()), which silently dropped assets/io.svg -
        referenced by popup.html - from every release archive. This runs
        the real builder against the real extension/ source and confirms
        every file that exists on disk actually makes it into the zip."""
        import importlib.util
        import tempfile
        import zipfile

        spec = importlib.util.spec_from_file_location(
            "build_extension", ROOT / "scripts" / "build_extension.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        with tempfile.TemporaryDirectory() as tmpdir:
            module.DIST = Path(tmpdir)
            manifest = json.loads((EXTENSION / "manifest.json").read_text(encoding="utf-8"))
            archive_path = module.build("chrome", manifest)

            expected = {
                str(p.relative_to(EXTENSION))
                for p in EXTENSION.rglob("*")
                if p.is_file()
            }
            with zipfile.ZipFile(archive_path) as archive:
                actual = set(archive.namelist())

            self.assertEqual(expected, actual)
            self.assertIn("assets/io.svg", actual)

            # popup.html references this path directly - confirm it's not
            # just present in the zip but findable at the exact path the
            # extension expects when it's unpacked/loaded.
            popup_html = (EXTENSION / "popup.html").read_text(encoding="utf-8")
            self.assertIn("assets/io.svg", popup_html)


if __name__ == "__main__":
    unittest.main()
