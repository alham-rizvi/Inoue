import unittest
from unittest.mock import MagicMock, patch

from core.scanner import (
    Detection,
    ScanResult,
    _check_dnssec,
    _extract_crawl_candidates,
    _extract_katana_candidates,
    _extract_sitemap_candidates,
    _get_ip_whois,
    _get_ptr_records,
    scan,
)


class SitemapCrawlTests(unittest.TestCase):
    @patch("httpx.Client")
    def test_parses_simple_sitemap(self, mock_client):
        response = MagicMock()
        response.status_code = 200
        response.text = """<?xml version="1.0"?>
<urlset><url><loc>https://example.com/a</loc></url>
<url><loc>https://example.com/b</loc></url></urlset>"""
        mock_client.return_value.__enter__.return_value.get.return_value = response
        urls = _extract_sitemap_candidates("https://example.com", limit=5)
        self.assertEqual(urls, ["https://example.com/a", "https://example.com/b"])

    @patch("httpx.Client")
    def test_follows_sitemap_index_one_level(self, mock_client):
        index_response = MagicMock()
        index_response.status_code = 200
        index_response.text = '<sitemapindex><sitemap><loc>https://example.com/sitemap1.xml</loc></sitemap></sitemapindex>'
        nested_response = MagicMock()
        nested_response.status_code = 200
        nested_response.text = '<urlset><url><loc>https://example.com/nested</loc></url></urlset>'
        mock_client.return_value.__enter__.return_value.get.side_effect = [index_response, nested_response]
        urls = _extract_sitemap_candidates("https://example.com", limit=5)
        self.assertEqual(urls, ["https://example.com/nested"])

    @patch("httpx.Client")
    def test_filters_off_origin_urls(self, mock_client):
        response = MagicMock()
        response.status_code = 200
        response.text = '<urlset><url><loc>https://evil.example/x</loc></url><url><loc>https://example.com/ok</loc></url></urlset>'
        mock_client.return_value.__enter__.return_value.get.return_value = response
        urls = _extract_sitemap_candidates("https://example.com", limit=5)
        self.assertEqual(urls, ["https://example.com/ok"])

    @patch("httpx.Client")
    def test_missing_sitemap_returns_empty(self, mock_client):
        response = MagicMock()
        response.status_code = 404
        response.text = ""
        mock_client.return_value.__enter__.return_value.get.return_value = response
        self.assertEqual(_extract_sitemap_candidates("https://example.com"), [])

    @patch("httpx.Client")
    def test_request_failure_degrades_to_empty(self, mock_client):
        mock_client.return_value.__enter__.return_value.get.side_effect = RuntimeError("boom")
        self.assertEqual(_extract_sitemap_candidates("https://example.com"), [])


class KatanaCrawlCandidateTests(unittest.TestCase):
    @patch("core.external_tools.run_katana")
    def test_filters_katana_results_to_same_origin(self, mock_katana):
        mock_katana.return_value = {
            "tool": "katana", "available": True,
            "results": ["https://example.com/app", "https://cdn.other.com/x"],
            "error": None, "note": None,
        }
        urls = _extract_katana_candidates("https://example.com", limit=5)
        self.assertEqual(urls, ["https://example.com/app"])

    @patch("core.external_tools.run_katana")
    def test_katana_unavailable_returns_empty(self, mock_katana):
        mock_katana.return_value = {"tool": "katana", "available": False, "results": [], "error": None, "note": "not found"}
        self.assertEqual(_extract_katana_candidates("https://example.com"), [])


class CombinedCrawlCandidateTests(unittest.TestCase):
    @patch("core.scanner._extract_sitemap_candidates", return_value=["https://example.com/sitemap-page"])
    def test_sitemap_candidates_are_combined_with_onpage_links(self, _):
        body = '<a href="/about">About</a>'
        candidates = _extract_crawl_candidates(body, "https://example.com/", limit=5)
        self.assertIn("https://example.com/sitemap-page", candidates)
        self.assertIn("https://example.com/about", candidates)

    @patch("core.scanner._extract_sitemap_candidates", return_value=[f"https://example.com/s{i}" for i in range(10)])
    def test_respects_overall_limit_across_sources(self, _):
        body = '<a href="/about">About</a>'
        candidates = _extract_crawl_candidates(body, "https://example.com/", limit=3)
        self.assertEqual(len(candidates), 3)

    @patch("core.scanner._extract_katana_candidates", return_value=["https://example.com/katana-page"])
    def test_katana_only_used_when_requested(self, mock_katana):
        _extract_crawl_candidates("", "https://example.com/", limit=5, use_sitemap=False, use_katana=False)
        mock_katana.assert_not_called()
        result = _extract_crawl_candidates("", "https://example.com/", limit=5, use_sitemap=False, use_katana=True)
        mock_katana.assert_called_once()
        self.assertIn("https://example.com/katana-page", result)


class DnsRecordExpansionTests(unittest.TestCase):
    def test_check_dnssec_returns_expected_shape_without_dnspython(self):
        with patch.dict("sys.modules", {"dns.resolver": None, "dns": None}):
            result = _check_dnssec("example.com")
        self.assertIn("ds_present", result)
        self.assertIn("dnskey_present", result)


class PtrAndIpWhoisTests(unittest.TestCase):
    @patch("socket.gethostbyaddr")
    def test_ptr_lookup_success(self, mock_gethostbyaddr):
        mock_gethostbyaddr.return_value = ("lb-1-2-3-4-iad.example.com", [], ["1.2.3.4"])
        records = _get_ptr_records(["1.2.3.4"])
        self.assertEqual(records["1.2.3.4"], "lb-1-2-3-4-iad.example.com")

    @patch("socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_ptr_lookup_failure_is_silently_skipped(self, _):
        self.assertEqual(_get_ptr_records(["1.2.3.4"]), {})

    def test_ptr_lookup_skips_empty_ips(self):
        self.assertEqual(_get_ptr_records(["", None]), {})

    @patch("httpx.Client")
    def test_ip_whois_parses_rdap_response(self, mock_client):
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "handle": "NET-1-2-3-0-1", "name": "EXAMPLE-NET", "type": "DIRECT ALLOCATION",
            "startAddress": "1.2.3.0", "endAddress": "1.2.3.255", "country": "US",
            "entities": [{"handle": "EX1-ARIN", "roles": ["registrant"]}],
        }
        mock_client.return_value.__enter__.return_value.get.return_value = response
        result = _get_ip_whois("1.2.3.4")
        self.assertEqual(result["name"], "EXAMPLE-NET")
        self.assertEqual(result["entities"][0]["handle"], "EX1-ARIN")

    @patch("httpx.Client")
    def test_ip_whois_handles_non_200(self, mock_client):
        response = MagicMock()
        response.status_code = 404
        mock_client.return_value.__enter__.return_value.get.return_value = response
        result = _get_ip_whois("1.2.3.4")
        self.assertIn("error", result)

    def test_ip_whois_empty_ip_returns_empty_dict(self):
        self.assertEqual(_get_ip_whois(""), {})


if __name__ == "__main__":
    unittest.main()
