import unittest
from unittest.mock import MagicMock, patch

from core.scanner import scan
from core.security_grade import detect_cors_misconfig, grade_security_headers


class SecurityHeaderGradingTests(unittest.TestCase):
    def test_all_headers_present_scores_100(self):
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }
        result = grade_security_headers(headers)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["missing"], [])

    def test_no_headers_scores_zero(self):
        result = grade_security_headers({})
        self.assertEqual(result["score"], 0)
        self.assertEqual(len(result["missing"]), 6)

    def test_partial_headers_scores_proportionally(self):
        result = grade_security_headers({"strict-transport-security": "max-age=1", "x-frame-options": "DENY"})
        self.assertEqual(result["score"], 33)  # 2/6 rounded

    def test_empty_value_counts_as_missing(self):
        result = grade_security_headers({"content-security-policy": "   "})
        names = {m["header"] for m in result["missing"]}
        self.assertIn("content-security-policy", names)

    def test_header_matching_is_case_insensitive(self):
        result = grade_security_headers({"Strict-Transport-Security": "max-age=1"})
        self.assertIn("strict-transport-security", result["present"])

    def test_missing_entries_include_explanation(self):
        result = grade_security_headers({})
        for entry in result["missing"]:
            self.assertIn("why_it_matters", entry)
            self.assertTrue(len(entry["why_it_matters"]) > 10)


class CorsMisconfigTests(unittest.TestCase):
    def test_wildcard_origin_with_credentials_is_flagged(self):
        findings = detect_cors_misconfig({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        })
        self.assertEqual(len(findings), 1)
        self.assertIn("Wildcard", findings[0]["issue"])

    def test_wildcard_without_credentials_is_not_flagged(self):
        """A bare '*' with no credentials header is the normal, safe way
        to serve a public API - flagging it would be pure noise."""
        findings = detect_cors_misconfig({"access-control-allow-origin": "*"})
        self.assertEqual(findings, [])

    def test_specific_origin_with_credentials_is_flagged_for_review(self):
        findings = detect_cors_misconfig({
            "access-control-allow-origin": "https://partner.example.com",
            "access-control-allow-credentials": "true",
        })
        self.assertEqual(len(findings), 1)
        self.assertIn("reflected", findings[0]["issue"])

    def test_no_cors_headers_returns_empty(self):
        self.assertEqual(detect_cors_misconfig({}), [])

    def test_credentials_false_is_never_flagged(self):
        findings = detect_cors_misconfig({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "false",
        })
        self.assertEqual(findings, [])

    def test_null_origin_with_credentials_not_flagged_as_specific_origin(self):
        # "null" origin is its own can of worms but shouldn't be reported
        # as a normal "specific origin" finding - not what this check targets.
        findings = detect_cors_misconfig({
            "access-control-allow-origin": "null",
            "access-control-allow-credentials": "true",
        })
        self.assertEqual(findings, [])

    def test_headers_are_case_insensitive(self):
        findings = detect_cors_misconfig({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "TRUE",
        })
        self.assertEqual(len(findings), 1)


class ScannerSecurityGradeWiringTests(unittest.TestCase):
    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_populates_security_grade_unconditionally(self, mock_get):
        """Regression guard: security_grade/cors_misconfig were originally
        written into result.enriched BEFORE the point in scan() where
        result.enriched gets fully reassigned to a fresh dict - which
        would have silently wiped them out every time. This confirms they
        survive to the final result."""
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {"strict-transport-security": "max-age=1"}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response

        result = scan("https://example.com", modules=["dns"], dns=False)

        self.assertIn("security_grade", result.enriched)
        self.assertIn("strict-transport-security", result.enriched["security_grade"]["present"])

    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_populates_cors_misconfig_when_present(self, mock_get):
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response

        result = scan("https://example.com", modules=["fast"])

        self.assertIn("cors_misconfig", result.enriched)

    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_omits_cors_misconfig_key_when_clean(self, mock_get):
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response

        result = scan("https://example.com", modules=["fast"])

        self.assertNotIn("cors_misconfig", result.enriched)


if __name__ == "__main__":
    unittest.main()
