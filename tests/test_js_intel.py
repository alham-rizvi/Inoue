import unittest
from unittest.mock import MagicMock, patch

from core.js_intel import (
    collect_script_urls,
    detect_secret_patterns,
    extract_endpoints,
    extract_hydration_payloads,
    fetch_js_bundles,
    harvest,
)
from core.scanner import Detection, ScanResult, _merge_js_intel, scan


class ScriptUrlCollectionTests(unittest.TestCase):
    def test_collects_absolute_and_relative_scripts(self):
        body = '<script src="/static/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
        urls = collect_script_urls(body, "https://example.com/")
        self.assertIn("https://example.com/static/app.js", urls)
        self.assertIn("https://cdn.example.com/lib.js", urls)

    def test_does_not_restrict_to_exact_origin(self):
        """Regression guard: an earlier draft filtered to the page's exact
        origin, which silently excluded the extremely common case of a
        site serving its own scripts from a dedicated asset domain."""
        body = '<script src="https://assets.githubusercontent-style-cdn.com/app.js"></script>'
        urls = collect_script_urls(body, "https://example.com/")
        self.assertEqual(len(urls), 1)

    def test_dedupes_repeated_script_tags(self):
        body = '<script src="/app.js"></script><script src="/app.js"></script>'
        urls = collect_script_urls(body, "https://example.com/")
        self.assertEqual(len(urls), 1)

    def test_empty_body_returns_empty_list(self):
        self.assertEqual(collect_script_urls("", "https://example.com/"), [])

    def test_prefers_bundle_looking_paths_over_trackers_when_over_limit(self):
        body = "".join([
            '<script src="https://www.googletagmanager.com/gtag/js"></script>',
            '<script src="/static/js/main.a1b2c3.js"></script>',
            '<script src="https://connect.facebook.net/en_US/fbevents.js"></script>',
            '<script src="/static/js/vendor.chunk.js"></script>',
        ])
        urls = collect_script_urls(body, "https://example.com/", limit=2)
        self.assertEqual(len(urls), 2)
        self.assertTrue(all("main" in u or "chunk" in u for u in urls))


class HydrationPayloadTests(unittest.TestCase):
    def test_detects_nextjs_marker(self):
        body = '<script>window.__NEXT_DATA__ = {"props":{}}</script>'
        findings = extract_hydration_payloads(body)
        frameworks = {f["framework"] for f in findings}
        self.assertIn("Next.js", frameworks)

    def test_detects_multiple_markers(self):
        body = "window.__NEXT_DATA__ = {}; window.__APOLLO_STATE__ = {};"
        findings = extract_hydration_payloads(body)
        self.assertEqual(len(findings), 2)

    def test_no_markers_returns_empty(self):
        self.assertEqual(extract_hydration_payloads("<html><body>plain page</body></html>"), [])

    def test_empty_body_returns_empty(self):
        self.assertEqual(extract_hydration_payloads(""), [])


class EndpointExtractionTests(unittest.TestCase):
    def test_extracts_api_paths_from_string_literals(self):
        bundles = {"a.js": 'fetch("/api/v2/users").then(r => r.json());'}
        endpoints = extract_endpoints(bundles)
        self.assertIn("/api/v2/users", endpoints)

    def test_dedupes_across_bundles(self):
        bundles = {
            "a.js": 'fetch("/api/user")',
            "b.js": 'axios.get("/api/user")',
        }
        endpoints = extract_endpoints(bundles)
        self.assertEqual(endpoints.count("/api/user"), 1)

    def test_no_endpoints_found_returns_empty(self):
        self.assertEqual(extract_endpoints({"a.js": "var x = 1;"}), [])

    def test_respects_limit(self):
        bundles = {"a.js": " ".join(f'"/api/v1/thing{i}"' for i in range(100))}
        endpoints = extract_endpoints(bundles, limit=10)
        self.assertEqual(len(endpoints), 10)


class SecretRedactionTests(unittest.TestCase):
    def test_aws_key_is_detected_and_redacted(self):
        fake_key = "AKIA" + "Q" * 16  # shape-valid, not a real credential
        bundles = {"a.js": f'const cfg = {{ accessKeyId: "{fake_key}" }};'}
        findings = detect_secret_patterns(bundles)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["type"], "AWS Access Key ID")
        # the full key must never appear in the output, only a redacted form
        self.assertNotIn(fake_key, findings[0]["redacted"])
        self.assertTrue(findings[0]["redacted"].startswith(fake_key[:4]))
        self.assertTrue(findings[0]["redacted"].endswith(fake_key[-4:]))
        self.assertIn("*", findings[0]["redacted"])

    def test_stripe_live_key_detected(self):
        fake_key = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0"
        bundles = {"a.js": f'stripe.setApiKey("{fake_key}")'}
        findings = detect_secret_patterns(bundles)
        types = {f["type"] for f in findings}
        self.assertIn("Stripe Live Secret Key", types)

    def test_generic_bearer_assignment_detected(self):
        bundles = {"a.js": 'const apiKey = "abcdefghijklmnopqrstuvwx1234567890";'}
        findings = detect_secret_patterns(bundles)
        self.assertTrue(len(findings) >= 1)

    def test_clean_bundle_finds_nothing(self):
        bundles = {"a.js": "function add(a,b){return a+b;} console.log(add(1,2));"}
        self.assertEqual(detect_secret_patterns(bundles), [])

    def test_dedupes_repeated_finding_across_bundles(self):
        fake_key = "AKIA" + "Q" * 16
        bundles = {"a.js": f'"{fake_key}"', "b.js": f'"{fake_key}"'}
        findings = detect_secret_patterns(bundles)
        self.assertEqual(len(findings), 1)

    def test_short_values_are_not_flagged(self):
        bundles = {"a.js": 'const token = "short";'}
        self.assertEqual(detect_secret_patterns(bundles), [])


class FetchJsBundlesTests(unittest.TestCase):
    @patch("httpx.Client")
    def test_fetches_and_truncates_bundle(self, mock_client):
        response = MagicMock()
        response.status_code = 200
        response.text = "x" * 1_000_000  # bigger than MAX_BUNDLE_BYTES
        mock_client.return_value.__enter__.return_value.get.return_value = response
        bundles = fetch_js_bundles(["https://example.com/app.js"])
        self.assertEqual(len(bundles["https://example.com/app.js"]), 500_000)

    @patch("httpx.Client")
    def test_failed_fetch_is_skipped_not_raised(self, mock_client):
        mock_client.return_value.__enter__.return_value.get.side_effect = RuntimeError("boom")
        bundles = fetch_js_bundles(["https://example.com/app.js"])
        self.assertEqual(bundles, {})

    @patch("httpx.Client")
    def test_non_200_is_skipped(self, mock_client):
        response = MagicMock()
        response.status_code = 404
        response.text = ""
        mock_client.return_value.__enter__.return_value.get.return_value = response
        bundles = fetch_js_bundles(["https://example.com/app.js"])
        self.assertEqual(bundles, {})


class HarvestOrchestrationTests(unittest.TestCase):
    @patch("core.js_intel.fetch_js_bundles")
    def test_harvest_combines_all_signals(self, mock_fetch):
        mock_fetch.return_value = {"https://example.com/app.js": 'fetch("/api/v1/x")'}
        body = '<script>window.__NEXT_DATA__={}</script><script src="/app.js"></script>'
        result = harvest(body, "https://example.com/")
        self.assertEqual(result["hydration_payloads"][0]["framework"], "Next.js")
        self.assertIn("/api/v1/x", result["endpoints"])
        self.assertIn("bundle_text", result)


class ScannerJsIntelMergeTests(unittest.TestCase):
    def _base_result(self):
        return ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)

    def test_merge_stores_metadata_without_leaking_bundle_text(self):
        result = self._base_result()
        payload = {
            "hydration_payloads": [{"marker": "window.__NEXT_DATA__", "framework": "Next.js"}],
            "scripts_fetched": ["https://example.com/app.js"],
            "scripts_attempted": ["https://example.com/app.js"],
            "endpoints": ["/api/v1/user"],
            "secret_findings": [],
            "bundle_text": {"https://example.com/app.js": "some content"},
        }
        _merge_js_intel(result, payload)
        stored = result.enriched["js_intel"]
        self.assertNotIn("bundle_text", stored)
        self.assertEqual(stored["endpoints"], ["/api/v1/user"])

    def test_merge_adds_low_confidence_bundle_only_detections(self):
        """The specific regression this guards against: JS-bundle-derived
        detections were being silently dropped because a confidence filter
        copied from crawl-mode excluded 'low' - but a framework marker
        found only in JS text can never score above low (no headers/meta
        to corroborate it), so filtering it out defeats the whole feature."""
        result = self._base_result()
        payload = {
            "hydration_payloads": [], "scripts_fetched": ["https://example.com/app.js"],
            "scripts_attempted": ["https://example.com/app.js"], "endpoints": [], "secret_findings": [],
            "bundle_text": {"https://example.com/app.js": "junk react.production.min.js junk __reactFiber$x"},
        }
        _merge_js_intel(result, payload)
        names = {t.name for t in result.technologies}
        self.assertIn("React", names)
        react = next(t for t in result.technologies if t.name == "React")
        self.assertTrue(react.evidence.startswith("[JS bundle]"))

    def test_merge_does_not_duplicate_already_detected_technology(self):
        result = self._base_result()
        result.technologies.append(Detection(name="React", category="JS Framework", confidence="high"))
        payload = {
            "hydration_payloads": [], "scripts_fetched": ["https://example.com/app.js"],
            "scripts_attempted": ["https://example.com/app.js"], "endpoints": [], "secret_findings": [],
            "bundle_text": {"https://example.com/app.js": "react.production.min.js"},
        }
        _merge_js_intel(result, payload)
        self.assertEqual(len([t for t in result.technologies if t.name == "React"]), 1)

    def test_merge_handles_none_payload(self):
        result = self._base_result()
        _merge_js_intel(result, None)
        self.assertNotIn("js_intel", result.enriched)

    def test_merge_handles_empty_bundle_text(self):
        result = self._base_result()
        payload = {"hydration_payloads": [], "scripts_fetched": [], "scripts_attempted": [], "endpoints": [], "secret_findings": [], "bundle_text": {}}
        _merge_js_intel(result, payload)
        self.assertEqual(result.technologies, [])
        self.assertIn("js_intel", result.enriched)


class ScanWiringTests(unittest.TestCase):
    @patch("core.scanner._run_js_intel")
    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_calls_js_intel_when_flag_set(self, mock_get, mock_js_intel):
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response
        mock_js_intel.return_value = {
            "hydration_payloads": [], "scripts_fetched": [], "scripts_attempted": [],
            "endpoints": [], "secret_findings": [], "bundle_text": {},
        }

        result = scan("https://example.com", modules=["fast"], js_intel=True, js_intel_bundles=2)

        mock_js_intel.assert_called_once()
        self.assertIn("js_intel", result.enriched)

    @patch("core.scanner._run_js_intel")
    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_skips_js_intel_when_flag_off(self, mock_get, mock_js_intel):
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response

        result = scan("https://example.com", modules=["fast"])

        mock_js_intel.assert_not_called()
        self.assertNotIn("js_intel", result.enriched)


if __name__ == "__main__":
    unittest.main()
