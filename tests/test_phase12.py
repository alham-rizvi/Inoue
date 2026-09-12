import unittest

from core.js_intel import grade_security_headers, parse_bundle, script_sources
from core.scope import RequestBudget, ScopeMatcher
from core.scanner import build_recon_plan
from core.waf import detect_waf


class ScopeTests(unittest.TestCase):
    def test_wildcard_and_cidr_matching(self):
        matcher = ScopeMatcher(["*.example.com", "203.0.113.0/24"])
        self.assertTrue(matcher.check("https://api.example.com"))
        self.assertTrue(matcher.check("https://203.0.113.9"))
        self.assertFalse(matcher.check("https://example.com"))

    def test_deny_overrides_allow(self):
        matcher = ScopeMatcher(["*.example.com"], ["*.internal.example.com"])
        self.assertFalse(matcher.check("https://dev.internal.example.com"))
        self.assertTrue(matcher.check("https://www.example.com"))

    def test_request_budget_is_bounded(self):
        budget = RequestBudget(2)
        self.assertTrue(budget.consume())
        self.assertTrue(budget.consume())
        self.assertFalse(budget.consume())
        self.assertEqual(budget.remaining, 0)


class WAFTests(unittest.TestCase):
    def test_cloudflare_header_and_cookie(self):
        detections = detect_waf({"cf-ray": "abc", "server": "cloudflare"}, {"cf_clearance": "redacted"})
        self.assertEqual({item.name for item in detections}, {"Cloudflare"})

    def test_no_waf_false_positive(self):
        self.assertEqual(detect_waf({"server": "nginx"}, {}), [])

    def test_module_plan_gating(self):
        self.assertFalse(build_recon_plan(["dns"]).get("waf"))
        self.assertTrue(build_recon_plan(["waf"]).get("waf"))
        self.assertTrue(build_recon_plan(["js-intel"]).get("js_intel"))


class JSIntelTests(unittest.TestCase):
    def test_script_sources_and_bundle_parsing(self):
        html = '<script src="/static/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
        self.assertEqual(script_sources(html, "https://example.com/"), ["https://example.com/static/app.js", "https://cdn.example.com/lib.js"])
        parsed = parse_bundle("fetch('/api/v1/users?id=1'); const host='https://internal.example.com'; const k='AKIA1234567890ABCDEF12';")
        self.assertIn("/api/v1/users?id=1", parsed["fetch_calls"])
        self.assertIn("internal.example.com", parsed["hosts"])
        self.assertTrue(parsed["secrets"][0]["value"].startswith("AKIA"))
        self.assertNotIn("1234567890", parsed["secrets"][0]["value"])

    def test_security_header_grade_and_cors(self):
        result = grade_security_headers({"access-control-allow-origin": "*", "access-control-allow-credentials": "true"})
        self.assertEqual(result["grade"], "D")
        self.assertTrue(result["cors"]["credentials_with_wildcard"])


if __name__ == "__main__":
    unittest.main()
