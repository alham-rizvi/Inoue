import unittest
from unittest.mock import MagicMock, patch

from core.api_discovery import check_graphql_introspection, discover_api_docs
from core.risk import rank_results, score_result
from core.scanner import Detection, ScanResult
from core.takeover import check_takeover, check_takeover_batch


def _mock_get(status=200, text="", json_payload=None):
    response = MagicMock()
    response.status_code = status
    response.text = text
    response.headers = {"content-type": "application/json"}
    if json_payload is not None:
        response.json.return_value = json_payload
    else:
        response.json.side_effect = ValueError("not json")
    return response


class TakeoverTests(unittest.TestCase):
    @patch("httpx.Client")
    def test_s3_unclaimed_bucket_detected(self, client):
        client.return_value.__enter__.return_value.get.return_value = _mock_get(
            404, "<html>NoSuchBucket - The specified bucket does not exist</html>"
        )
        finding = check_takeover("files.example.com", cname="files.s3.amazonaws.com")
        self.assertEqual(finding["service"], "AWS S3")
        self.assertEqual(finding["confidence"], "high")

    @patch("httpx.Client")
    def test_confidence_is_medium_without_cname_corroboration(self, client):
        client.return_value.__enter__.return_value.get.return_value = _mock_get(
            404, "<html>NoSuchBucket</html>"
        )
        finding = check_takeover("files.example.com")
        self.assertEqual(finding["confidence"], "medium")

    @patch("httpx.Client")
    def test_github_pages_detected(self, client):
        client.return_value.__enter__.return_value.get.return_value = _mock_get(
            404, "There isn't a GitHub Pages site here."
        )
        finding = check_takeover("docs.example.com", cname="example.github.io")
        self.assertEqual(finding["service"], "GitHub Pages")

    @patch("httpx.Client")
    def test_healthy_site_is_not_flagged(self, client):
        client.return_value.__enter__.return_value.get.return_value = _mock_get(
            200, "<html><body>Welcome to our site</body></html>"
        )
        self.assertIsNone(check_takeover("www.example.com"))

    @patch("httpx.Client")
    def test_generic_404_requires_cname_corroboration(self, client):
        """A bare '404 Not Found' body is far too common to report on its
        own - without a CNAME pointing at the matching service it must not
        produce a finding."""
        client.return_value.__enter__.return_value.get.return_value = _mock_get(404, "404 Not Found")
        self.assertIsNone(check_takeover("random.example.com"))

    @patch("httpx.Client")
    def test_request_failure_returns_none(self, client):
        client.return_value.__enter__.return_value.get.side_effect = RuntimeError("boom")
        self.assertIsNone(check_takeover("dead.example.com"))

    @patch("core.takeover.check_takeover")
    def test_batch_respects_max_hosts(self, mock_check):
        mock_check.return_value = None
        hosts = [f"h{i}.example.com" for i in range(100)]
        check_takeover_batch(hosts, max_hosts=5)
        self.assertEqual(mock_check.call_count, 5)

    def test_batch_with_no_hosts_returns_empty(self):
        self.assertEqual(check_takeover_batch([]), [])

    def test_finding_carries_a_verify_manually_caveat(self):
        with patch("httpx.Client") as client:
            client.return_value.__enter__.return_value.get.return_value = _mock_get(404, "NoSuchBucket")
            finding = check_takeover("x.example.com")
        self.assertIn("Candidate only", finding["caveat"])


class ApiDiscoveryTests(unittest.TestCase):
    @patch("core.api_discovery._probe")
    def test_openapi_spec_detected_with_path_count(self, probe):
        def side_effect(url, timeout):
            if url.endswith("/openapi.json"):
                spec = '{"openapi":"3.0.0","info":{"title":"Demo"},"paths":{"/a":{},"/b":{}}}'
                return _mock_get(200, spec)
            return _mock_get(404)
        probe.side_effect = side_effect
        findings = discover_api_docs("https://example.com")
        spec = next(f for f in findings if f["kind"] == "OpenAPI/Swagger spec")
        self.assertIn("Demo", spec["detail"])
        self.assertIn("2 documented paths", spec["detail"])

    @patch("core.api_discovery._probe")
    def test_security_txt_detected(self, probe):
        def side_effect(url, timeout):
            if url.endswith("security.txt"):
                return _mock_get(200, "Contact: mailto:security@example.com")
            return _mock_get(404)
        probe.side_effect = side_effect
        findings = discover_api_docs("https://example.com")
        self.assertTrue(any(f["kind"] == "security.txt" for f in findings))

    @patch("core.api_discovery._probe", return_value=_mock_get(404))
    def test_nothing_found_returns_empty(self, _):
        self.assertEqual(discover_api_docs("https://example.com"), [])

    @patch("httpx.Client")
    def test_graphql_introspection_enabled_detected(self, client):
        client.return_value.__enter__.return_value.post.return_value = _mock_get(
            200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
            {"data": {"__schema": {"queryType": {"name": "Query"}}}},
        )
        findings = check_graphql_introspection("https://example.com")
        self.assertTrue(findings[0]["introspection_enabled"])
        self.assertIn("ENABLED", findings[0]["detail"])

    @patch("httpx.Client")
    def test_graphql_introspection_disabled_detected(self, client):
        client.return_value.__enter__.return_value.post.return_value = _mock_get(
            400, '{"errors":[{"message":"introspection disabled"}]}',
            {"errors": [{"message": "introspection disabled"}]},
        )
        findings = check_graphql_introspection("https://example.com")
        self.assertFalse(findings[0]["introspection_enabled"])

    @patch("httpx.Client")
    def test_no_graphql_endpoint_returns_empty(self, client):
        client.return_value.__enter__.return_value.post.return_value = _mock_get(404, "Not Found")
        self.assertEqual(check_graphql_introspection("https://example.com"), [])


class RiskScoringTests(unittest.TestCase):
    def _result(self, **enriched):
        result = ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)
        result.enriched = dict(enriched)
        result.waf = enriched.pop("_waf", []) if "_waf" in enriched else []
        return result

    def test_clean_target_scores_zero(self):
        result = self._result(security_grade={"score": 100}, api_surface={})
        result.waf = [{"name": "Cloudflare"}]
        scored = score_result(result)
        self.assertEqual(scored["score"], 0)
        self.assertEqual(scored["band"], "nothing-notable")

    def test_takeover_candidate_drives_high_score(self):
        result = self._result(takeover_candidates=[{"hostname": "x.example.com", "service": "AWS S3"}])
        result.waf = [{"name": "Cloudflare"}]
        scored = score_result(result)
        self.assertGreaterEqual(scored["score"], 40)
        self.assertEqual(scored["band"], "investigate-first")

    def test_security_txt_is_not_counted_as_risk(self):
        """Regression guard: security.txt is a published disclosure policy -
        a good practice - and an OIDC discovery doc is expected IdP
        behaviour. Neither should inflate a risk score."""
        result = self._result(api_surface={
            "api_docs": [
                {"kind": "security.txt", "url": "https://example.com/.well-known/security.txt"},
                {"kind": "OpenID Connect discovery", "url": "https://example.com/.well-known/openid-configuration"},
            ],
            "summary": {"docs_found": 2, "introspection_enabled": False},
        })
        result.waf = [{"name": "Cloudflare"}]
        scored = score_result(result)
        factors = {f["factor"] for f in scored["factors"]}
        self.assertNotIn("openapi_spec_exposed", factors)

    def test_openapi_spec_is_counted_as_risk(self):
        result = self._result(api_surface={
            "api_docs": [{"kind": "OpenAPI/Swagger spec", "url": "https://example.com/openapi.json"}],
            "summary": {"docs_found": 1, "introspection_enabled": False},
        })
        result.waf = [{"name": "Cloudflare"}]
        scored = score_result(result)
        factors = {f["factor"] for f in scored["factors"]}
        self.assertIn("openapi_spec_exposed", factors)

    def test_missing_waf_is_a_factor(self):
        result = self._result()
        scored = score_result(result)
        self.assertIn("no_waf", {f["factor"] for f in scored["factors"]})

    def test_leaked_secret_is_weighted_heavily(self):
        result = self._result(js_intel={"secret_findings": [{"type": "AWS Access Key ID", "source": "app.js"}]})
        result.waf = [{"name": "Cloudflare"}]
        scored = score_result(result)
        self.assertGreaterEqual(scored["score"], 35)

    def test_critical_cve_counted_from_technologies(self):
        result = self._result()
        result.waf = [{"name": "Cloudflare"}]
        result.technologies = [Detection(name="X", category="Other", cves=[{"severity": "critical"}])]
        scored = score_result(result)
        self.assertIn("critical_cve", {f["factor"] for f in scored["factors"]})

    def test_score_is_capped_at_100(self):
        result = self._result(
            takeover_candidates=[{"hostname": f"h{i}", "service": "S3"} for i in range(10)],
            js_intel={"secret_findings": [{"type": "AWS", "source": "a.js"}] * 10},
        )
        scored = score_result(result)
        self.assertEqual(scored["score"], 100)

    def test_result_carries_triage_caveat(self):
        scored = score_result(self._result())
        self.assertIn("not a severity rating", scored["caveat"])

    def test_rank_results_orders_by_score_descending(self):
        clean = self._result(security_grade={"score": 100})
        clean.waf = [{"name": "Cloudflare"}]
        risky = self._result(takeover_candidates=[{"hostname": "x", "service": "S3"}])
        risky.final_url = "https://risky.example.com"
        ranked = rank_results([clean, risky])
        self.assertEqual(ranked[0]["target"], "https://risky.example.com")

    def test_rank_results_skips_errored_scans(self):
        broken = self._result()
        broken.error = "connection failed"
        self.assertEqual(rank_results([broken]), [])


if __name__ == "__main__":
    unittest.main()
