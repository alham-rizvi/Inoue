import unittest

from core.cve import correlate_cves
from core.scanner import Detection, ScanResult, diff_scan_results
from core.tls_fingerprint import fingerprint_tls, known_tls_fingerprints
from core.webhooks import build_discord_payload, build_generic_payload, build_slack_payload


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


if __name__ == "__main__":
    unittest.main()
