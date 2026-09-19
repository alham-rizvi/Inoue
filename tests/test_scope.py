import unittest
from unittest.mock import MagicMock, patch

from core.scope import Scope, filter_hosts, parse_scope_file


class ScopeMatchingTests(unittest.TestCase):
    def test_unrestricted_scope_allows_everything(self):
        scope = Scope()
        self.assertTrue(scope.is_unrestricted)
        self.assertTrue(scope.allows("anything.example.com"))

    def test_exact_domain_allowed(self):
        scope = Scope(allow_domains=["example.com"])
        self.assertTrue(scope.allows("example.com"))
        self.assertFalse(scope.allows("other.com"))

    def test_wildcard_subdomain_allowed(self):
        scope = Scope(allow_domains=["*.example.com"])
        self.assertTrue(scope.allows("www.example.com"))
        self.assertTrue(scope.allows("api.example.com"))
        self.assertTrue(scope.allows("example.com"))  # bare apex also matches *.
        self.assertFalse(scope.allows("evil.com"))

    def test_wildcard_does_not_match_unrelated_suffix(self):
        scope = Scope(allow_domains=["*.example.com"])
        self.assertFalse(scope.allows("notexample.com"))
        self.assertFalse(scope.allows("example.com.evil.com"))

    def test_deny_overrides_broader_allow(self):
        scope = Scope(allow_domains=["*.example.com"], deny_domains=["internal.example.com"])
        self.assertTrue(scope.allows("www.example.com"))
        self.assertFalse(scope.allows("internal.example.com"))

    def test_ip_in_allowed_network(self):
        import ipaddress
        scope = Scope(allow_networks=[ipaddress.ip_network("10.0.0.0/8")])
        self.assertTrue(scope.allows("some-host", ip="10.1.2.3"))
        self.assertFalse(scope.allows("some-host", ip="192.168.1.1"))

    def test_ip_deny_overrides_allow(self):
        import ipaddress
        scope = Scope(
            allow_networks=[ipaddress.ip_network("10.0.0.0/8")],
            deny_networks=[ipaddress.ip_network("10.1.0.0/16")],
        )
        self.assertTrue(scope.allows("h", ip="10.0.0.1"))
        self.assertFalse(scope.allows("h", ip="10.1.0.1"))

    def test_hostname_matching_is_case_insensitive_and_ignores_trailing_dot(self):
        scope = Scope(allow_domains=["example.com"])
        self.assertTrue(scope.allows("EXAMPLE.COM."))

    def test_invalid_ip_does_not_crash(self):
        import ipaddress
        scope = Scope(allow_networks=[ipaddress.ip_network("10.0.0.0/8")])
        # restricted scope with no matching domain and a garbage IP - must
        # resolve to False cleanly, not raise
        self.assertFalse(scope.allows("host", ip="not-an-ip"))


class ScopeFileParsingTests(unittest.TestCase):
    def _write(self, tmp_path, content):
        tmp_path.write_text(content)
        return str(tmp_path)

    def test_missing_file_is_unrestricted(self):
        scope = parse_scope_file("/nonexistent/path/scope.txt")
        self.assertTrue(scope.is_unrestricted)

    def test_parses_domains_wildcards_and_cidrs(self, tmp_path=None):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("example.com\n*.example.com\n10.0.0.0/8\n")
            scope = parse_scope_file(str(path))
        self.assertIn("example.com", scope.allow_domains)
        self.assertIn("*.example.com", scope.allow_domains)
        self.assertEqual(len(scope.allow_networks), 1)

    def test_comments_and_blank_lines_are_ignored(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("# a comment\n\nexample.com  # inline comment\n\n")
            scope = parse_scope_file(str(path))
        self.assertEqual(scope.allow_domains, ["example.com"])

    def test_deny_prefix_parsed_into_deny_lists(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("*.example.com\n!internal.example.com\n!10.1.0.0/16\n")
            scope = parse_scope_file(str(path))
        self.assertIn("internal.example.com", scope.deny_domains)
        self.assertEqual(len(scope.deny_networks), 1)

    def test_lowercases_domain_entries(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("EXAMPLE.COM\n")
            scope = parse_scope_file(str(path))
        self.assertEqual(scope.allow_domains, ["example.com"])


class FilterHostsTests(unittest.TestCase):
    def test_none_scope_passes_everything_through(self):
        self.assertEqual(filter_hosts(["a.com", "b.com"], None), ["a.com", "b.com"])

    def test_unrestricted_scope_passes_everything_through(self):
        self.assertEqual(filter_hosts(["a.com", "b.com"], Scope()), ["a.com", "b.com"])

    def test_filters_out_of_scope_hosts(self):
        scope = Scope(allow_domains=["*.example.com"])
        result = filter_hosts(["www.example.com", "evil.com", "api.example.com"], scope)
        self.assertEqual(result, ["www.example.com", "api.example.com"])

    def test_empty_host_list_is_safe(self):
        self.assertEqual(filter_hosts([], Scope(allow_domains=["example.com"])), [])


class ScanScopeEnforcementTests(unittest.TestCase):
    @patch("core.scanner._get_with_redirect_policy")
    def test_out_of_scope_target_is_refused_before_any_request(self, mock_get):
        import tempfile
        from pathlib import Path
        from core.scanner import scan

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("allowed-only.example.com\n")
            result = scan("https://not-allowed.example.com", modules=["fast"], scope_file=str(path))

        self.assertIsNotNone(result.error)
        self.assertIn("not in scope", result.error)
        mock_get.assert_not_called()

    @patch("core.scanner._get_with_redirect_policy")
    def test_in_scope_target_proceeds_normally(self, mock_get):
        import tempfile
        from pathlib import Path
        from core.scanner import scan

        fake = MagicMock()
        fake.url = "https://allowed.example.com/"
        fake.status_code = 200
        fake.headers = {}
        fake.cookies.items.return_value = []
        fake.text = "<html></html>"
        mock_get.return_value = fake

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("allowed.example.com\n")
            result = scan("https://allowed.example.com", modules=["fast"], scope_file=str(path))

        self.assertIsNone(result.error)
        mock_get.assert_called_once()

    @patch("core.scanner._get_with_redirect_policy")
    def test_no_scope_file_means_unrestricted(self, mock_get):
        from core.scanner import scan

        fake = MagicMock()
        fake.url = "https://anything.example.com/"
        fake.status_code = 200
        fake.headers = {}
        fake.cookies.items.return_value = []
        fake.text = "<html></html>"
        mock_get.return_value = fake

        result = scan("https://anything.example.com", modules=["fast"])
        self.assertIsNone(result.error)


class TakeoverScopeFilteringTests(unittest.TestCase):
    """The highest-risk fanout point: subdomain discovery can surface hosts
    well outside the explicitly-typed target, and every one gets a live GET."""

    @patch("core.takeover.check_takeover_batch")
    def test_out_of_scope_discovered_subdomains_are_never_probed(self, mock_batch):
        import tempfile
        from pathlib import Path
        from core.scanner import _run_takeover_check

        mock_batch.return_value = []
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("example.com\n*.example.com\n")
            _run_takeover_check(
                "example.com",
                subdomains=[{"subdomain": "www.example.com"}, {"subdomain": "totally-unrelated.other.com"}],
                dns_records={},
                timeout=5,
                scope_file=str(path),
            )

        probed_hosts = mock_batch.call_args[0][0]
        self.assertIn("example.com", probed_hosts)
        self.assertIn("www.example.com", probed_hosts)
        self.assertNotIn("totally-unrelated.other.com", probed_hosts)

    @patch("core.takeover.check_takeover_batch")
    def test_no_scope_file_probes_all_discovered_hosts(self, mock_batch):
        from core.scanner import _run_takeover_check

        mock_batch.return_value = []
        _run_takeover_check(
            "example.com",
            subdomains=[{"subdomain": "anything.example.com"}],
            dns_records={},
            timeout=5,
        )
        probed_hosts = mock_batch.call_args[0][0]
        self.assertIn("anything.example.com", probed_hosts)

    @patch("core.takeover.check_takeover_batch")
    def test_target_itself_excluded_if_out_of_scope(self, mock_batch):
        """A scope file always wins, even over the hostname passed in directly."""
        import tempfile
        from pathlib import Path
        from core.scanner import _run_takeover_check

        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "scope.txt"
            path.write_text("other.example.com\n")
            _run_takeover_check("not-in-scope.example.com", subdomains=[], dns_records={}, timeout=5, scope_file=str(path))

        mock_batch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
