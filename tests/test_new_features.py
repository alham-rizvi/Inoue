import unittest
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from core.favicon import compute_favicon_hash, extract_favicon_href, match_favicon_hash
from core.history import build_timeline, clear_history, list_snapshots, record_snapshot
from core.scanner import (
    Detection,
    ScanResult,
    _extract_crawl_candidates,
    _get_favicon,
    _merge_crawl_and_favicon,
    _serialize_scan_result,
    run_fingerprints,
    scan,
)
from inoue import app
import json


class FaviconHashingTests(unittest.TestCase):
    def test_compute_favicon_hash_is_deterministic_md5(self):
        content = b"\x00\x01\x02fake-favicon-bytes"
        first = compute_favicon_hash(content)
        second = compute_favicon_hash(content)
        self.assertEqual(first["md5"], second["md5"])
        self.assertEqual(len(first["md5"]), 32)

    def test_compute_favicon_hash_empty_content_returns_empty_dict(self):
        self.assertEqual(compute_favicon_hash(b""), {})

    def test_match_favicon_hash_hits_seeded_catalog_entry(self):
        content = b"known-icon-bytes"
        hashes = compute_favicon_hash(content)
        fake_catalog = {f"md5:{hashes['md5']}": ("TestCMS", "CMS")}
        with patch("core.favicon.FAVICON_HASHES", fake_catalog):
            match = match_favicon_hash(hashes)
        self.assertEqual(match, ("TestCMS", "CMS"))

    def test_match_favicon_hash_miss_returns_none(self):
        hashes = {"md5": "0" * 32}
        with patch("core.favicon.FAVICON_HASHES", {}):
            self.assertIsNone(match_favicon_hash(hashes))

    def test_extract_favicon_href_prefers_declared_link_tag(self):
        body = '<html><head><link rel="icon" href="/static/custom-icon.png"></head></html>'
        href = extract_favicon_href(body, "https://example.com/page")
        self.assertEqual(href, "https://example.com/static/custom-icon.png")

    def test_extract_favicon_href_falls_back_to_default_path(self):
        href = extract_favicon_href("<html></html>", "https://example.com/page")
        self.assertEqual(href, "https://example.com/favicon.ico")

    @patch("httpx.Client")
    def test_get_favicon_returns_hash_and_matched_technology(self, mock_client):
        response = MagicMock()
        response.status_code = 200
        response.content = b"known-icon-bytes"
        mock_client.return_value.__enter__.return_value.get.return_value = response

        fake_catalog = {f"md5:{compute_favicon_hash(b'known-icon-bytes')['md5']}": ("TestCMS", "CMS")}
        with patch("core.favicon.FAVICON_HASHES", fake_catalog):
            payload = _get_favicon("https://example.com", "<html></html>", timeout=5)

        self.assertIsNotNone(payload)
        self.assertEqual(payload["matched_technology"], "TestCMS")
        self.assertEqual(payload["matched_category"], "CMS")
        self.assertEqual(payload["url"], "https://example.com/favicon.ico")

    @patch("httpx.Client")
    def test_get_favicon_returns_none_on_request_failure(self, mock_client):
        mock_client.return_value.__enter__.return_value.get.side_effect = RuntimeError("boom")
        payload = _get_favicon("https://example.com", "<html></html>", timeout=5)
        self.assertIsNone(payload)

    @patch("httpx.Client")
    def test_get_favicon_returns_none_on_404(self, mock_client):
        response = MagicMock()
        response.status_code = 404
        response.content = b""
        mock_client.return_value.__enter__.return_value.get.return_value = response
        payload = _get_favicon("https://example.com", "<html></html>", timeout=5)
        self.assertIsNone(payload)


class CrawlCandidateTests(unittest.TestCase):
    def test_extract_crawl_candidates_stays_same_origin(self):
        body = """
        <html><body>
        <a href="/about">About</a>
        <a href="https://example.com/pricing">Pricing</a>
        <a href="https://other-site.com/evil">Off-site</a>
        <a href="mailto:hi@example.com">Email</a>
        <a href="#section">Anchor</a>
        <a href="/about">Duplicate</a>
        </body></html>
        """
        candidates = _extract_crawl_candidates(body, "https://example.com/", limit=5)
        self.assertIn("https://example.com/about", candidates)
        self.assertIn("https://example.com/pricing", candidates)
        self.assertNotIn("https://other-site.com/evil", candidates)
        self.assertEqual(len(candidates), len(set(candidates)))

    def test_extract_crawl_candidates_respects_limit(self):
        body = "".join(f'<a href="/page{i}">p{i}</a>' for i in range(20))
        candidates = _extract_crawl_candidates(body, "https://example.com/", limit=3)
        self.assertEqual(len(candidates), 3)

    def test_extract_crawl_candidates_disabled_when_limit_zero(self):
        body = '<a href="/about">About</a>'
        self.assertEqual(_extract_crawl_candidates(body, "https://example.com/", limit=0), [])

    def test_extract_crawl_candidates_empty_body(self):
        self.assertEqual(_extract_crawl_candidates("", "https://example.com/", limit=5), [])


class MergeCrawlAndFaviconTests(unittest.TestCase):
    def test_favicon_match_is_added_as_new_detection(self):
        result = ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)
        favicon_payload = {"url": "https://example.com/favicon.ico", "md5": "abc", "matched_technology": "TestCMS", "matched_category": "CMS"}
        _merge_crawl_and_favicon(result, favicon_payload, [], [])
        names = {tech.name for tech in result.technologies}
        self.assertIn("TestCMS", names)
        self.assertEqual(result.extra_intel["favicon"], favicon_payload)

    def test_favicon_match_does_not_duplicate_existing_detection(self):
        result = ScanResult(
            url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0,
            technologies=[Detection(name="TestCMS", category="CMS", confidence="high")],
        )
        favicon_payload = {"url": "https://example.com/favicon.ico", "md5": "abc", "matched_technology": "TestCMS", "matched_category": "CMS"}
        _merge_crawl_and_favicon(result, favicon_payload, [], [])
        self.assertEqual(len([t for t in result.technologies if t.name == "TestCMS"]), 1)

    def test_crawl_detections_are_merged_and_pages_recorded(self):
        result = ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)
        crawl_detections = [Detection(name="Stripe", category="Payments", confidence="high", evidence="[https://example.com/checkout] script")]
        _merge_crawl_and_favicon(result, None, crawl_detections, ["https://example.com/checkout"])
        names = {tech.name for tech in result.technologies}
        self.assertIn("Stripe", names)
        self.assertEqual(result.enriched["crawl"]["pages_scanned"], ["https://example.com/checkout"])

    def test_crawl_detection_does_not_override_existing_technology(self):
        result = ScanResult(
            url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0,
            technologies=[Detection(name="Stripe", category="Payments", confidence="low")],
        )
        crawl_detections = [Detection(name="Stripe", category="Payments", confidence="high")]
        _merge_crawl_and_favicon(result, None, crawl_detections, ["https://example.com/checkout"])
        self.assertEqual(len(result.technologies), 1)
        self.assertEqual(result.technologies[0].confidence, "low")


class ConfidenceThresholdTests(unittest.TestCase):
    def test_low_confidence_for_a_single_weak_signal(self):
        sig_name = "__low_confidence_fixture__"
        from fingerprints.signatures import COMPILED_SIGNATURES, SIGNATURES
        import re
        SIGNATURES[sig_name] = {"category": "Other", "cookies": ["low_conf_cookie"]}
        COMPILED_SIGNATURES[sig_name] = {"category": "Other", "cookies": [re.compile("low_conf_cookie", re.I)]}
        try:
            detections = run_fingerprints({}, {"low_conf_cookie": "1"}, "", url="https://example.com")
            match = next(d for d in detections if d.name == sig_name)
            self.assertEqual(match.confidence, "low")
        finally:
            SIGNATURES.pop(sig_name, None)
            COMPILED_SIGNATURES.pop(sig_name, None)

    def test_medium_confidence_for_a_single_strong_signal(self):
        sig_name = "__medium_confidence_fixture__"
        from fingerprints.signatures import COMPILED_SIGNATURES, SIGNATURES
        import re
        SIGNATURES[sig_name] = {"category": "Other", "headers": {"x-fixture-header": None}}
        COMPILED_SIGNATURES[sig_name] = {"category": "Other", "headers": {"x-fixture-header": re.compile(".*")}}
        try:
            detections = run_fingerprints({"x-fixture-header": "present"}, {}, "", url="https://example.com")
            match = next(d for d in detections if d.name == sig_name)
            self.assertEqual(match.confidence, "medium")
        finally:
            SIGNATURES.pop(sig_name, None)
            COMPILED_SIGNATURES.pop(sig_name, None)

    def test_high_confidence_requires_multiple_agreeing_signals(self):
        sig_name = "__high_confidence_fixture__"
        from fingerprints.signatures import COMPILED_SIGNATURES, SIGNATURES, SIGNATURES_BY_HEADER, SIGNATURES_BY_META
        import re
        SIGNATURES[sig_name] = {
            "category": "Other",
            "headers": {"x-fixture-header": None},
            "meta": {"generator": None},
        }
        COMPILED_SIGNATURES[sig_name] = {
            "category": "Other",
            "headers": {"x-fixture-header": re.compile(".*")},
            "meta": {"generator": re.compile("fixture", re.I)},
        }
        SIGNATURES_BY_HEADER.setdefault("x-fixture-header", []).append(sig_name)
        SIGNATURES_BY_META.setdefault("generator", []).append(sig_name)
        try:
            body = '<meta name="generator" content="fixture 1.0">'
            detections = run_fingerprints({"x-fixture-header": "present"}, {}, body, url="https://example.com")
            match = next(d for d in detections if d.name == sig_name)
            self.assertEqual(match.confidence, "high")
        finally:
            SIGNATURES.pop(sig_name, None)
            COMPILED_SIGNATURES.pop(sig_name, None)
            SIGNATURES_BY_HEADER.get("x-fixture-header", []).remove(sig_name) if sig_name in SIGNATURES_BY_HEADER.get("x-fixture-header", []) else None
            SIGNATURES_BY_META.get("generator", []).remove(sig_name) if sig_name in SIGNATURES_BY_META.get("generator", []) else None


class HistoryStoreTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "history.db")

    def tearDown(self):
        self.tmpdir.cleanup()

    def _result(self, technologies):
        return ScanResult(
            url="https://example.com", final_url="https://example.com/", status_code=200,
            response_time_ms=1.0, technologies=technologies,
        )

    def test_record_and_list_snapshots_round_trips(self):
        record_snapshot(self.db_path, "https://example.com", _serialize_scan_result(self._result([Detection("Nginx", "Web Server")])))
        snapshots = list_snapshots(self.db_path, "https://example.com")
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["result"]["technologies"][0]["name"], "Nginx")

    def test_snapshots_are_append_only_not_overwritten(self):
        record_snapshot(self.db_path, "https://example.com", _serialize_scan_result(self._result([Detection("Nginx", "Web Server")])))
        record_snapshot(self.db_path, "https://example.com", _serialize_scan_result(self._result([Detection("Apache", "Web Server")])))
        snapshots = list_snapshots(self.db_path, "https://example.com")
        self.assertEqual(len(snapshots), 2)

    def test_build_timeline_detects_added_and_removed_technology(self):
        record_snapshot(self.db_path, "https://example.com", _serialize_scan_result(self._result([Detection("Nginx", "Web Server", version="1.24")])))
        record_snapshot(self.db_path, "https://example.com", _serialize_scan_result(self._result([Detection("Nginx", "Web Server", version="1.26")])))
        timeline = build_timeline(self.db_path, "https://example.com")
        self.assertEqual(len(timeline), 1)
        change = timeline[0]["diff"]["technology_changes"][0]
        self.assertEqual(change["status"], "changed")
        self.assertEqual(change["previous"], "1.24")
        self.assertEqual(change["current"], "1.26")

    def test_list_snapshots_for_unknown_target_is_empty(self):
        self.assertEqual(list_snapshots(self.db_path, "https://never-scanned.example"), [])

    def test_clear_history_removes_only_target_when_specified(self):
        record_snapshot(self.db_path, "https://a.example", _serialize_scan_result(self._result([])))
        record_snapshot(self.db_path, "https://b.example", _serialize_scan_result(self._result([])))
        clear_history(self.db_path, "https://a.example")
        self.assertEqual(list_snapshots(self.db_path, "https://a.example"), [])
        self.assertEqual(len(list_snapshots(self.db_path, "https://b.example")), 1)


class HistoryCliTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        from pathlib import Path
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmpdir.name) / "history.db")

    def tearDown(self):
        self.tmpdir.cleanup()

    @patch("inoue.scan")
    def test_save_history_flag_persists_snapshot(self, mock_scan):
        mock_scan.return_value = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=1.0,
            technologies=[Detection("Nginx", "Web Server", version="1.26.0")],
        )
        runner = CliRunner()
        result = runner.invoke(
            app,
            ["--no-banner", "--save-history", "--history-path", self.db_path, "example.com"],
            catch_exceptions=False,
        )
        self.assertEqual(result.exit_code, 0)

        from core.history import list_snapshots
        snapshots = list_snapshots(self.db_path, "https://example.com")
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["result"]["technologies"][0]["name"], "Nginx")

    @patch("inoue.scan")
    def test_scan_without_save_history_flag_does_not_write_db(self, mock_scan):
        mock_scan.return_value = ScanResult(
            url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0,
        )
        runner = CliRunner()
        runner.invoke(app, ["--no-banner", "--history-path", self.db_path, "example.com"], catch_exceptions=False)
        from pathlib import Path
        self.assertFalse(Path(self.db_path).exists())

    def test_history_command_reports_no_history_for_unknown_target(self):
        runner = CliRunner()
        result = runner.invoke(app, ["history", "never-scanned.example", "--history-path", self.db_path], catch_exceptions=False)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("no saved history", result.stdout)

    def test_history_command_json_output_is_valid_json(self):
        runner = CliRunner()
        result = runner.invoke(
            app, ["history", "never-scanned.example", "--history-path", self.db_path, "--json"], catch_exceptions=False,
        )
        payload = json.loads(result.stdout)
        self.assertEqual(payload["snapshots"], 0)

    @patch("inoue.scan")
    def test_history_command_shows_technology_change_after_two_scans(self, mock_scan):
        runner = CliRunner()
        mock_scan.return_value = ScanResult(
            url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0,
            technologies=[Detection("Nginx", "Web Server", version="1.24.0")],
        )
        runner.invoke(app, ["--no-banner", "--save-history", "--history-path", self.db_path, "example.com"], catch_exceptions=False)

        mock_scan.return_value = ScanResult(
            url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0,
            technologies=[Detection("Nginx", "Web Server", version="1.26.0")],
        )
        runner.invoke(app, ["--no-banner", "--save-history", "--history-path", self.db_path, "example.com"], catch_exceptions=False)

        result = runner.invoke(app, ["history", "example.com", "--history-path", self.db_path], catch_exceptions=False)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Nginx", result.stdout)
        self.assertIn("1.24.0", result.stdout)
        self.assertIn("1.26.0", result.stdout)


class CrawlCliWiringTests(unittest.TestCase):
    @patch("inoue.scan")
    def test_crawl_flag_is_forwarded_to_scan(self, mock_scan):
        mock_scan.return_value = ScanResult(
            url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0,
        )
        runner = CliRunner()
        runner.invoke(app, ["--no-banner", "--crawl", "3", "example.com"], catch_exceptions=False)
        _, kwargs = mock_scan.call_args
        self.assertEqual(kwargs["crawl_pages"], 3)

    @patch("inoue.scan")
    def test_crawl_defaults_to_zero(self, mock_scan):
        mock_scan.return_value = ScanResult(
            url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0,
        )
        runner = CliRunner()
        runner.invoke(app, ["--no-banner", "example.com"], catch_exceptions=False)
        _, kwargs = mock_scan.call_args
        self.assertEqual(kwargs["crawl_pages"], 0)


class DnsOnlyDoesNotFingerprintTests(unittest.TestCase):
    """Regression test for: requesting a single non-tech module (e.g. --dns)
    used to still run the full technology fingerprint matcher against every
    signature in the catalog. Only DNS/whois/ssl/etc. should run."""

    @patch("core.scanner._get_dns")
    @patch("core.scanner.run_fingerprints")
    def test_dns_only_module_skips_fingerprinting(self, mock_fingerprints, mock_dns):
        mock_dns.return_value = {"A": ["93.184.216.34"]}

        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {"server": "nginx"}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"

        with patch("httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value = MagicMock(
                get=MagicMock(return_value=fake_response)
            )
            with patch("core.scanner._get_with_redirect_policy", return_value=fake_response):
                result = scan("https://example.com", modules=["dns"], dns=True)

        mock_fingerprints.assert_not_called()
        self.assertEqual(result.technologies, [])
        self.assertEqual(result.dns_records, {"A": ["93.184.216.34"]})

    @patch("core.scanner.run_fingerprints")
    def test_default_scan_still_runs_fingerprinting(self, mock_fingerprints):
        mock_fingerprints.return_value = [Detection("Nginx", "Web Server")]

        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {"server": "nginx"}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"

        with patch("core.scanner._get_with_redirect_policy", return_value=fake_response):
            result = scan("https://example.com", modules=None)

        mock_fingerprints.assert_called_once()
        self.assertEqual(result.technologies[0].name, "Nginx")


class SerializerExposesCrawlTests(unittest.TestCase):
    def test_serialize_scan_result_includes_crawl_metadata(self):
        from core.scanner import serialize_scan_result
        result = ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)
        result.enriched["crawl"] = {"pages_scanned": ["https://example.com/about"]}
        payload = serialize_scan_result(result)
        self.assertEqual(payload["crawl"], {"pages_scanned": ["https://example.com/about"]})

    def test_serialize_scan_result_crawl_defaults_to_empty_dict(self):
        from core.scanner import serialize_scan_result
        result = ScanResult(url="https://example.com", final_url="https://example.com", status_code=200, response_time_ms=1.0)
        payload = serialize_scan_result(result)
        self.assertEqual(payload["crawl"], {})


if __name__ == "__main__":
    unittest.main()
