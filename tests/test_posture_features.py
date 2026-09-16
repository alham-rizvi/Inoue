import unittest
from unittest.mock import MagicMock, patch

from core.email_security import analyze_dmarc, analyze_spf
from core.http_posture import (
    analyze_csp,
    analyze_redirect_chain,
    audit_cookies,
    check_http_methods,
)


class SpfTests(unittest.TestCase):
    @patch("core.email_security._txt_records")
    def test_hardfail_policy_has_no_issue(self, txt):
        txt.return_value = (["v=spf1 include:_spf.google.com -all"], True)
        result = analyze_spf("example.com")
        self.assertEqual(result["policy"], "hardfail")
        self.assertIsNone(result["issue"])

    @patch("core.email_security._txt_records")
    def test_pass_all_is_flagged(self, txt):
        txt.return_value = (["v=spf1 +all"], True)
        result = analyze_spf("example.com")
        self.assertEqual(result["policy"], "pass-all")
        self.assertIn("ANY host", result["issue"])

    @patch("core.email_security._txt_records")
    def test_neutral_is_flagged(self, txt):
        txt.return_value = (["v=spf1 ?all"], True)
        self.assertIn("no enforcement", analyze_spf("example.com")["issue"])

    @patch("core.email_security._txt_records")
    def test_multiple_spf_records_flagged_as_invalid(self, txt):
        txt.return_value = (["v=spf1 -all", "v=spf1 include:x -all"], True)
        result = analyze_spf("example.com")
        self.assertEqual(result["policy"], "invalid")
        self.assertIn("permerror", result["issue"])

    @patch("core.email_security._txt_records")
    def test_genuine_absence_is_reported(self, txt):
        txt.return_value = ([], True)
        result = analyze_spf("example.com")
        self.assertFalse(result["present"])
        self.assertIn("No SPF record", result["issue"])

    @patch("core.email_security._txt_records")
    def test_lookup_failure_is_not_reported_as_absence(self, txt):
        """Regression guard for a real bug: a DNS timeout was being reported
        as 'No SPF record published - anyone can send mail as this domain',
        which is a confidently wrong security claim. A failed lookup must
        never be presented as established absence."""
        txt.return_value = ([], False)
        result = analyze_spf("example.com")
        self.assertIsNone(result["present"])
        self.assertTrue(result["lookup_failed"])
        self.assertIsNone(result["issue"])


class DmarcTests(unittest.TestCase):
    @patch("core.email_security._txt_records")
    def test_reject_policy_has_no_issue(self, txt):
        txt.return_value = (["v=DMARC1; p=reject; rua=mailto:a@b.com"], True)
        result = analyze_dmarc("example.com")
        self.assertEqual(result["policy"], "reject")
        self.assertIsNone(result["issue"])
        self.assertTrue(result["rua"])

    @patch("core.email_security._txt_records")
    def test_p_none_is_flagged_as_monitor_only(self, txt):
        txt.return_value = (["v=DMARC1; p=none"], True)
        self.assertIn("monitor only", analyze_dmarc("example.com")["issue"])

    @patch("core.email_security._txt_records")
    def test_partial_pct_is_flagged(self, txt):
        txt.return_value = (["v=DMARC1; p=reject; pct=20"], True)
        result = analyze_dmarc("example.com")
        self.assertEqual(result["pct"], 20)
        self.assertIn("20%", result["issue"])

    @patch("core.email_security._txt_records")
    def test_lookup_failure_is_not_absence(self, txt):
        txt.return_value = ([], False)
        result = analyze_dmarc("example.com")
        self.assertTrue(result["lookup_failed"])
        self.assertIsNone(result["issue"])


class CookieAuditTests(unittest.TestCase):
    def test_session_cookie_missing_all_flags(self):
        findings = audit_cookies(["sessionid=abc; Path=/"])
        self.assertEqual(set(findings[0]["missing"]), {"Secure", "SameSite", "HttpOnly"})
        self.assertTrue(findings[0]["session_like"])

    def test_non_session_cookie_not_flagged_for_httponly(self):
        """A UI-preference cookie is intentionally JS-readable; flagging
        every such cookie for HttpOnly buries the real findings."""
        findings = audit_cookies(["theme=dark; Path=/"])
        self.assertNotIn("HttpOnly", findings[0]["missing"])

    def test_fully_secured_cookie_produces_no_finding(self):
        findings = audit_cookies(["sid=x; Secure; HttpOnly; SameSite=Strict"])
        self.assertEqual(findings, [])

    def test_empty_input_is_safe(self):
        self.assertEqual(audit_cookies([]), [])
        self.assertEqual(audit_cookies(None), [])


class CspTests(unittest.TestCase):
    def test_absent_csp(self):
        self.assertFalse(analyze_csp("")["present"])

    def test_unsafe_inline_and_eval_flagged(self):
        issues = [w["issue"] for w in analyze_csp("script-src 'unsafe-inline' 'unsafe-eval'")["weaknesses"]]
        self.assertIn("'unsafe-inline' allowed", issues)
        self.assertIn("'unsafe-eval' allowed", issues)

    def test_wildcard_in_script_src_flagged(self):
        issues = [w["issue"] for w in analyze_csp("script-src *")["weaknesses"]]
        self.assertIn("wildcard in script-src", issues)

    def test_strict_policy_has_few_weaknesses(self):
        result = analyze_csp("default-src 'self'; object-src 'none'; script-src 'self'")
        self.assertEqual(result["weaknesses"], [])


class RedirectChainTests(unittest.TestCase):
    def _hop(self, url, status=301):
        r = MagicMock()
        r.url = url
        r.status_code = status
        return r

    def test_https_downgrade_detected(self):
        history = [self._hop("https://example.com/")]
        result = analyze_redirect_chain(history, "http://example.com/final")
        self.assertTrue(result["https_downgrade"])
        self.assertTrue(result["issues"])

    def test_cross_host_detected(self):
        history = [self._hop("https://example.com/")]
        result = analyze_redirect_chain(history, "https://other.com/")
        self.assertTrue(result["cross_host"])

    def test_clean_chain_has_no_issues(self):
        history = [self._hop("https://example.com/")]
        result = analyze_redirect_chain(history, "https://example.com/final")
        self.assertEqual(result["issues"], [])

    def test_no_history_is_safe(self):
        result = analyze_redirect_chain(None, "https://example.com/")
        self.assertEqual(result["hop_count"], 0)


class HttpMethodTests(unittest.TestCase):
    @patch("httpx.Client")
    def test_risky_methods_flagged(self, client):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"allow": "GET, POST, PUT, DELETE, TRACE"}
        client.return_value.__enter__.return_value.options.return_value = response
        result = check_http_methods("https://example.com")
        risky = {m["method"] for m in result["risky"]}
        self.assertEqual(risky, {"PUT", "DELETE", "TRACE"})

    @patch("httpx.Client")
    def test_safe_methods_produce_no_risky_entries(self, client):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"allow": "GET, HEAD, OPTIONS"}
        client.return_value.__enter__.return_value.options.return_value = response
        self.assertEqual(check_http_methods("https://example.com")["risky"], [])

    @patch("httpx.Client")
    def test_request_failure_degrades_gracefully(self, client):
        client.return_value.__enter__.return_value.options.side_effect = RuntimeError("boom")
        result = check_http_methods("https://example.com")
        self.assertFalse(result["checked"])

    @patch("httpx.Client")
    def test_result_carries_not_proof_caveat(self, client):
        response = MagicMock()
        response.status_code = 200
        response.headers = {"allow": "PUT"}
        client.return_value.__enter__.return_value.options.return_value = response
        self.assertIn("not proof", check_http_methods("https://example.com")["note"])


if __name__ == "__main__":
    unittest.main()
