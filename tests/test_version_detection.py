import unittest

from core.scanner import (
    Detection,
    _aggressive_version_hunt,
    _slugify_tech_name,
    run_fingerprints,
)


class SlugifyTests(unittest.TestCase):
    def test_multiword_name_produces_common_url_forms(self):
        forms = set(_slugify_tech_name("Font Awesome"))
        self.assertIn("font-awesome", forms)
        self.assertIn("fontawesome", forms)
        self.assertIn("font_awesome", forms)

    def test_single_word_name(self):
        self.assertIn("sentry", _slugify_tech_name("Sentry"))

    def test_short_or_empty_names_are_dropped(self):
        self.assertEqual(_slugify_tech_name(""), [])
        self.assertEqual(_slugify_tech_name("!!"), [])


class AggressiveHuntTests(unittest.TestCase):
    def test_finds_version_in_script_url(self):
        scripts = ["/cpresources/craft-cms/4.5.6/app.js"]
        version, source = _aggressive_version_hunt("Craft CMS", "", scripts, {})
        self.assertEqual(version, "4.5.6")
        self.assertEqual(source, "script-url")

    def test_finds_version_preceding_the_name(self):
        scripts = ["https://cdn.example.com/3.6.0/jquery.min.js"]
        version, _ = _aggressive_version_hunt("jQuery", "", scripts, {})
        self.assertEqual(version, "3.6.0")

    def test_finds_version_in_header(self):
        headers = {"X-Generator": "SilverStripe 4.13.2"}
        version, source = _aggressive_version_hunt("SilverStripe", "", [], headers)
        self.assertEqual(version, "4.13.2")
        self.assertEqual(source, "header")

    def test_returns_nothing_when_name_absent(self):
        version, source = _aggressive_version_hunt("Craft CMS", "<html>nothing here</html>", [], {})
        self.assertIsNone(version)
        self.assertEqual(source, "")

    def test_returns_nothing_when_no_version_present(self):
        version, _ = _aggressive_version_hunt("Sentry", "<script>Sentry.init()</script>", [], {})
        self.assertIsNone(version)

    def test_script_url_wins_over_unrelated_html_number(self):
        body = "<p>Established 1998. Version 2.0 of our mission statement.</p>"
        scripts = ["/assets/craft-cms/4.5.6/app.js"]
        version, source = _aggressive_version_hunt("Craft CMS", body, scripts, {})
        self.assertEqual(version, "4.5.6")
        self.assertEqual(source, "script-url")


class VersionProvenanceTests(unittest.TestCase):
    def test_signature_parsed_version_is_labelled_signature(self):
        body = '<meta name="generator" content="Astro v4.5.0">'
        detections = run_fingerprints({}, {}, body, url="https://example.com")
        astro = next(d for d in detections if d.name == "Astro")
        self.assertEqual(astro.version, "4.5.0")
        self.assertEqual(astro.version_source, "signature")

    def test_hunted_version_is_labelled_with_its_source(self):
        """Craft CMS's signature is cookie-only, so the normal extraction
        path has no text to scan and would leave version as None."""
        body = '<html><head><script src="/cpresources/craft-cms/4.5.6/app.js"></script></head></html>'
        detections = run_fingerprints({}, {"CraftSessionId": "abc"}, body, url="https://example.com")
        craft = next(d for d in detections if d.name == "Craft CMS")
        self.assertEqual(craft.version, "4.5.6")
        self.assertEqual(craft.version_source, "script-url")

    def test_version_hunt_can_be_disabled(self):
        body = '<html><head><script src="/cpresources/craft-cms/4.5.6/app.js"></script></head></html>'
        detections = run_fingerprints(
            {}, {"CraftSessionId": "abc"}, body, url="https://example.com", version_hunt=False,
        )
        craft = next(d for d in detections if d.name == "Craft CMS")
        self.assertIsNone(craft.version)
        self.assertEqual(craft.version_source, "")

    def test_no_version_found_leaves_source_empty(self):
        detections = run_fingerprints({}, {"CraftSessionId": "abc"}, "<html></html>", url="https://example.com")
        craft = next(d for d in detections if d.name == "Craft CMS")
        self.assertIsNone(craft.version)
        self.assertEqual(craft.version_source, "")

    def test_detection_defaults_version_source_to_empty(self):
        self.assertEqual(Detection(name="X", category="Other").version_source, "")


if __name__ == "__main__":
    unittest.main()
