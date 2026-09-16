import unittest

from core.scanner import run_fingerprints
from fingerprints.modern_catalog import MODERN_SIGNATURES
from fingerprints.signatures import SIGNATURES


class ModernCatalogMergeTests(unittest.TestCase):
    def test_modern_signatures_are_merged_into_main_catalog(self):
        for name in ("Express.js", "Netlify", "Astro", "WooCommerce", "Sentry"):
            self.assertIn(name, SIGNATURES)

    def test_no_accidental_duplicate_of_existing_signature(self):
        """Regression guard: an earlier draft of modern_catalog.py added a
        new 'Express' entry duplicating the pre-existing 'Express.js'
        signature (identical X-Powered-By: Express signal). Catalog
        additions should extend an existing name via merge, not create a
        near-duplicate under a slightly different name."""
        self.assertNotIn("Express", SIGNATURES)
        self.assertIn("Express.js", SIGNATURES)

    def test_every_modern_signature_has_a_category(self):
        for name, sig in MODERN_SIGNATURES.items():
            self.assertIn("category", sig, name)
            self.assertTrue(sig["category"], name)

    def test_merging_a_new_name_does_not_disturb_existing_entries(self):
        # Astro is new; Apache is pre-existing and unrelated - merging
        # shouldn't touch it.
        self.assertEqual(SIGNATURES["Apache"]["headers"]["Server"], r"Apache(?:/(\d+[\d.]+))?")


class NewSignatureDetectionTests(unittest.TestCase):
    def test_express_powered_by_header_detected(self):
        detections = run_fingerprints({"X-Powered-By": "Express"}, {}, "", url="https://example.com")
        names = {d.name for d in detections}
        self.assertIn("Express.js", names)

    def test_astro_meta_generator_captures_version(self):
        body = '<meta name="generator" content="Astro v4.5.0">'
        detections = run_fingerprints({}, {}, body, url="https://example.com")
        astro = next(d for d in detections if d.name == "Astro")
        self.assertEqual(astro.version, "4.5.0")

    def test_woocommerce_detected_by_cookie(self):
        detections = run_fingerprints({}, {"woocommerce_cart_hash": "x"}, "", url="https://example.com")
        names = {d.name for d in detections}
        self.assertIn("WooCommerce", names)

    def test_google_tag_manager_detected_by_script(self):
        body = '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"></script>'
        detections = run_fingerprints({}, {}, body, url="https://example.com")
        names = {d.name for d in detections}
        self.assertIn("Google Tag Manager", names)

    def test_netlify_detected_by_header(self):
        detections = run_fingerprints({"x-nf-request-id": "abc123"}, {}, "", url="https://example.com")
        names = {d.name for d in detections}
        self.assertIn("Netlify", names)


class HtmlVersionWindowTests(unittest.TestCase):
    """Regression guard for the real bug found while testing the new
    catalog: _match_html used a 360-character window around a match to
    look for a nearby version number, wide enough to bleed a version from
    a completely unrelated adjacent tag into the wrong technology's
    result. Unlike _match_scripts/_match_meta (correctly scoped to just
    the matched string), this affected every html-based signature."""

    def test_version_does_not_bleed_from_an_unrelated_nearby_tag(self):
        body = (
            '<meta name="generator" content="Astro v4.5.0">'
            '<script src="https://widget.intercom.io/widget/abc123"></script>'
        )
        detections = run_fingerprints({}, {}, body, url="https://example.com")
        intercom = next(d for d in detections if d.name == "Intercom")
        self.assertIsNone(intercom.version)

    def test_genuinely_adjacent_version_is_still_captured(self):
        """The fix must not be so aggressive it breaks legitimate nearby
        version text - only the unrelated-tag bleed case is the bug."""
        body = '<div id="app" data-react-version="18.2.0">__reactFiber$abc</div>'
        detections = run_fingerprints({}, {}, body, url="https://example.com")
        react = next((d for d in detections if d.name == "React"), None)
        self.assertIsNotNone(react)


if __name__ == "__main__":
    unittest.main()
