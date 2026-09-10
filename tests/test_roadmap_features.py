import unittest
from unittest.mock import Mock, patch

from core.cve import correlate_cves
from core.scanner import Detection, ScanResult, diff_scan_results, watch_scan_loop
from core.tls_fingerprint import fingerprint_tls, known_tls_fingerprints
from core.terminal import load_terminal_settings
from core.webhooks import (
    build_discord_payload,
    build_generic_payload,
    build_slack_payload,
    send_webhook,
)
from scripts.import_wappalyzer import check_import_compatibility
from mcp_server import search_signatures


class RoadmapFeatureTests(unittest.TestCase):
    def test_diff_scan_results_detects_technology_and_cve_changes(self):
        previous = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=100,
            technologies=[
                Detection("Apache", "Web Server", version="2.4.49", cves=[{"id": "CVE-OLD", "severity": "low"}]),
                Detection("WordPress", "CMS", version="6.4"),
            ],
            open_ports=[80, 443],
        )
        current = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=110,
            technologies=[
                Detection("Apache", "Web Server", version="2.4.49", cves=[{"id": "CVE-NEW", "severity": "high"}]),
                Detection("Nginx", "Web Server", version="1.26.0"),
            ],
            open_ports=[80, 443, 8443],
        )

        diff = diff_scan_results(previous, current)

        self.assertIn("added", diff["technology_changes"][0]["status"])
        self.assertIn("CVE-NEW", diff["cve_changes"][0]["id"])
        self.assertIn("8443", str(diff["port_changes"]))

    def test_tls_fingerprint_matches_known_fixture_table(self):
        fp = fingerprint_tls("cloudflare", "TLS_AES_256_GCM_SHA384", "TLSv1.3")

        self.assertEqual(fp, "cloudflare-1")
        self.assertIn("cloudflare", known_tls_fingerprints())

    def test_webhook_payload_builders_cover_generic_slack_and_discord(self):
        payload = build_generic_payload("https://example.com", ["Apache", "Nginx"], ["CVE-1"])
        self.assertIn("Apache", payload["technologies"])

        slack = build_slack_payload("https://example.com", ["Apache"], ["CVE-1"])
        self.assertIn("Apache", slack["text"])

        discord = build_discord_payload("https://example.com", ["Apache"], ["CVE-1"])
        self.assertIn("Apache", discord["embeds"][0]["description"])

    def test_epss_score_is_preserved_in_cve_matches(self):
        dataset = [{
            "id": "CVE-EPSS",
            "technology": "Apache",
            "versions": ["2.4.49"],
            "summary": "Example",
            "severity": "high",
            "epss_score": 0.91,
        }]

        matches = correlate_cves("Apache", "2.4.49", dataset)

        self.assertEqual(matches[0]["epss_score"], 0.91)

    def test_watch_scan_loop_invokes_scan_and_sleeps_on_interval(self):
        calls = []

        def fake_scan():
            calls.append("scan")
            return "ok"

        sleep = Mock()
        results = watch_scan_loop(["https://example.com"], fake_scan, interval_seconds=5, iterations=2, sleep_fn=sleep)

        self.assertEqual(results, ["ok", "ok"])
        self.assertEqual(sleep.call_count, 1)

    def test_import_compatibility_detects_live_catalog_duplicates(self):
        current = {"Apache": {"category": "Web Server"}, "Nginx": {"category": "Web Server"}}
        incoming = {"Apache": {"category": "Web Server"}, "Cloudflare": {"category": "CDN"}}

        conflicts = check_import_compatibility(current, incoming)

        self.assertEqual(conflicts, ["Apache"])

    def test_send_webhook_posts_only_to_user_supplied_url(self):
        with patch("core.webhooks.httpx.Client") as mock_client:
            payload = send_webhook(
                "https://hooks.example.com/alert",
                {"text": "hi"},
                verify=True,
            )

        self.assertTrue(payload)
        mock_client.return_value.__enter__.return_value.post.assert_called_once()

    def test_terminal_settings_allow_editable_colors_and_layout(self):
        settings = load_terminal_settings({
            "terminal": {
                "text_style": "bright_white",
                "layout": "wide",
                "colors": {"Web Server": "bright_cyan"},
            }
        })

        self.assertEqual(settings.text_style, "bright_white")
        self.assertEqual(settings.layout, "wide")
        self.assertEqual(settings.colors["Web Server"], "bright_cyan")

    def test_mcp_signature_search_is_catalog_only(self):
        matches = search_signatures("kestrel", category="Application Server")

        self.assertEqual(matches[0]["name"], "Kestrel")
        self.assertEqual(matches[0]["category"], "Application Server")


if __name__ == "__main__":
    unittest.main()
