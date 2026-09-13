import unittest
from unittest.mock import MagicMock, patch

from core.scanner import scan
from core.waf import detect_waf


class WafSignatureTests(unittest.TestCase):
    def test_cloudflare_detected_by_header(self):
        findings = detect_waf({"cf-ray": "8a1b2c3d4e5f-IAD"}, {})
        names = {f["name"] for f in findings}
        self.assertIn("Cloudflare", names)

    def test_cloudflare_detected_by_cookie(self):
        findings = detect_waf({}, {"__cfduid": "abc123"})
        names = {f["name"] for f in findings}
        self.assertIn("Cloudflare", names)

    def test_cloudfront_detected_by_via_header(self):
        findings = detect_waf({"via": "1.1 abc123.cloudfront.net (CloudFront)"}, {})
        names = {f["name"] for f in findings}
        self.assertIn("AWS CloudFront", names)

    def test_akamai_detected(self):
        findings = detect_waf({"server": "AkamaiGHost"}, {})
        names = {f["name"] for f in findings}
        self.assertIn("Akamai", names)

    def test_incapsula_detected_by_cookie(self):
        findings = detect_waf({}, {"incap_ses_123_456789": "xyz"})
        names = {f["name"] for f in findings}
        self.assertIn("Imperva Incapsula", names)

    def test_sucuri_detected(self):
        findings = detect_waf({"x-sucuri-id": "12345"}, {})
        names = {f["name"] for f in findings}
        self.assertIn("Sucuri", names)

    def test_fastly_detected_by_x_served_by(self):
        findings = detect_waf({"x-served-by": "cache-iad-kcgs7200176-IAD"}, {})
        names = {f["name"] for f in findings}
        self.assertIn("Fastly", names)

    def test_azure_front_door_detected(self):
        findings = detect_waf({"x-azure-ref": "abc123"}, {})
        names = {f["name"] for f in findings}
        self.assertIn("Azure Front Door / WAF", names)

    def test_f5_detected_by_cookie_not_by_generic_header(self):
        # Regression guard: an earlier draft matched a generic "ts" cookie
        # and a generic "connection: close" header, both real false-positive
        # risks. Neither should trigger F5 on their own.
        self.assertEqual(detect_waf({"connection": "close"}, {"ts": "deadbeef12345678"}), [])
        findings = detect_waf({}, {"bigipserver_pool": "1234.5678.0000"})
        names = {f["name"] for f in findings}
        self.assertIn("F5 BIG-IP ASM", names)

    def test_no_false_positive_on_plain_server(self):
        findings = detect_waf({"server": "nginx/1.24.0", "content-type": "text/html"}, {"sessionid": "abc"})
        self.assertEqual(findings, [])

    def test_no_signals_returns_empty_list(self):
        self.assertEqual(detect_waf({}, {}), [])

    def test_multiple_wafs_can_be_reported_together(self):
        # Not unrealistic - a site can sit behind CloudFront with AWS WAF attached.
        findings = detect_waf({"x-amz-cf-id": "abc", "x-amzn-waf-action": "ALLOW"}, {})
        names = {f["name"] for f in findings}
        self.assertIn("AWS CloudFront", names)
        self.assertIn("AWS WAF", names)

    def test_each_finding_has_expected_shape(self):
        findings = detect_waf({"cf-ray": "abc"}, {})
        finding = findings[0]
        self.assertEqual(set(finding.keys()), {"name", "vendor", "category", "confidence", "evidence"})


class WafScannerWiringTests(unittest.TestCase):
    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_populates_waf_field(self, mock_get):
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {"cf-ray": "8a1b2c3d4e5f-IAD", "server": "cloudflare"}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response

        result = scan("https://example.com", modules=["fast"])

        names = {f["name"] for f in result.waf}
        self.assertIn("Cloudflare", names)

    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_waf_runs_even_on_dns_only_module(self, mock_get):
        """WAF detection is passive/free - it should still populate even
        when tech fingerprinting itself is skipped (e.g. --dns), since
        it costs nothing extra and doesn't touch the signature catalog."""
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {"cf-ray": "8a1b2c3d4e5f-IAD"}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response

        result = scan("https://example.com", modules=["dns"], dns=False)

        names = {f["name"] for f in result.waf}
        self.assertIn("Cloudflare", names)


if __name__ == "__main__":
    unittest.main()
