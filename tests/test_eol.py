import unittest
from datetime import date
from unittest.mock import MagicMock, patch

from core.eol import check_eol, check_technologies
from core.risk import score_result
from core.scanner import Detection, ScanResult


class EolLookupTests(unittest.TestCase):
    def test_php_74_is_eol(self):
        result = check_eol("PHP", "7.4.3", as_of=date(2026, 1, 1))
        self.assertTrue(result["is_eol"])
        self.assertEqual(result["eol_date"], "2022-11-28")
        self.assertGreater(result["days_past_eol"], 0)

    def test_php_84_not_yet_eol(self):
        result = check_eol("PHP", "8.4.1", as_of=date(2026, 1, 1))
        self.assertFalse(result["is_eol"])
        self.assertIsNotNone(result["days_until_eol"])

    def test_exact_eol_date_counts_as_eol(self):
        result = check_eol("PHP", "8.0.0", as_of=date(2023, 11, 26))
        self.assertTrue(result["is_eol"])
        self.assertEqual(result["days_past_eol"], 0)

    def test_day_before_eol_is_not_eol(self):
        result = check_eol("PHP", "8.0.0", as_of=date(2023, 11, 25))
        self.assertFalse(result["is_eol"])

    def test_nodejs_version_prefix_matching(self):
        result = check_eol("Node.js", "20.10.5", as_of=date(2027, 1, 1))
        self.assertTrue(result["is_eol"])
        self.assertEqual(result["eol_date"], "2026-04-30")

    def test_python_alias_lowercase_name_resolves(self):
        result = check_eol("python", "3.9.1", as_of=date(2026, 1, 1))
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "python")  # name preserved as given

    def test_unknown_technology_returns_none(self):
        self.assertIsNone(check_eol("SomeRandomThing", "1.0.0"))

    def test_unknown_version_of_known_technology_returns_none(self):
        """A version prefix that doesn't match any table entry (e.g. a very
        old or very new unlisted release) must be None, not a false 'not
        EOL' - the two mean different things and must not be conflated."""
        self.assertIsNone(check_eol("PHP", "9.9.9"))

    def test_empty_version_returns_none(self):
        self.assertIsNone(check_eol("PHP", ""))


class EolBatchTests(unittest.TestCase):
    def test_only_eol_technologies_are_returned(self):
        techs = [
            Detection(name="PHP", category="Language", version="7.4.3"),
            Detection(name="PHP", category="Language", version="8.4.0"),  # not EOL
            Detection(name="React", category="JS Framework", version="18.2.0"),  # not in table
        ]
        findings = check_technologies(techs, as_of=date(2026, 1, 1))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["version"], "7.4.3")

    def test_technologies_without_version_are_skipped(self):
        techs = [Detection(name="PHP", category="Language", version=None)]
        self.assertEqual(check_technologies(techs), [])

    def test_empty_list_returns_empty(self):
        self.assertEqual(check_technologies([]), [])
        self.assertEqual(check_technologies(None), [])


class EolRiskIntegrationTests(unittest.TestCase):
    def test_eol_finding_becomes_a_risk_factor(self):
        result = ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)
        result.waf = [{"name": "Cloudflare"}]
        result.enriched = {"eol_technologies": [{
            "name": "PHP", "version": "7.4.3", "eol_date": "2022-11-28",
            "is_eol": True, "days_past_eol": 1000, "source": "php.net",
        }]}
        scored = score_result(result)
        self.assertIn("eol_technology", {f["factor"] for f in scored["factors"]})

    def test_no_eol_findings_means_no_factor(self):
        result = ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)
        result.waf = [{"name": "Cloudflare"}]
        result.enriched = {}
        scored = score_result(result)
        self.assertNotIn("eol_technology", {f["factor"] for f in scored["factors"]})


class ScannerEolWiringTests(unittest.TestCase):
    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_detects_eol_php_from_header(self, mock_get):
        fake = MagicMock()
        fake.url = "https://example.com/"
        fake.status_code = 200
        fake.headers = {"X-Powered-By": "PHP/7.4.3"}
        fake.cookies.items.return_value = []
        fake.text = "<html></html>"
        mock_get.return_value = fake

        from core.scanner import scan
        result = scan("https://example.com", modules=["fast"])

        eol = result.enriched.get("eol_technologies")
        self.assertTrue(eol)
        self.assertEqual(eol[0]["name"], "PHP")
        self.assertIn("eol_technology", {f["factor"] for f in result.enriched["risk"]["factors"]})

    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_without_eol_tech_has_no_key(self, mock_get):
        fake = MagicMock()
        fake.url = "https://example.com/"
        fake.status_code = 200
        fake.headers = {}
        fake.cookies.items.return_value = []
        fake.text = "<html></html>"
        mock_get.return_value = fake

        from core.scanner import scan
        result = scan("https://example.com", modules=["fast"])

        self.assertNotIn("eol_technologies", result.enriched)


if __name__ == "__main__":
    unittest.main()
