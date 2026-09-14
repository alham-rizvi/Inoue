import unittest
from unittest.mock import MagicMock, patch

import mcp_server
from mcp_server import (
    catalog_summary,
    check_security_headers,
    check_waf,
    get_scan_history,
    scan_target,
    search_signatures,
)


class SdkCompatibilityTests(unittest.TestCase):
    """Regression coverage for the real bug this session found: the mcp
    package renamed FastMCP -> MCPServer between v1 and v2, and the
    original single-path import silently swallowed the resulting
    ModuleNotFoundError (a subclass of ImportError) behind a bare
    `except ImportError`, reporting "not installed" even when an
    incompatible version WAS installed."""

    @unittest.skipUnless(mcp_server.mcp is not None, "optional mcp SDK is not installed")
    def test_mcp_server_base_resolved_in_this_environment(self):
        """This sandbox has the real mcp package installed - confirm the
        module actually resolved a usable server class, not silently None."""
        self.assertIsNotNone(mcp_server.MCPServerBase)
        self.assertIsNotNone(mcp_server.mcp)
        self.assertIsNone(mcp_server._MCP_IMPORT_ERROR)

    def test_falls_back_to_v1_when_v2_import_fails(self):
        def broken_v2():
            raise ImportError("No module named 'mcp.server.mcpserver'")

        fake_v1_class = object()

        def fake_v1():
            return fake_v1_class

        server_class, error = mcp_server._import_mcp_server_base(import_v2=broken_v2, import_v1=fake_v1)
        self.assertIs(server_class, fake_v1_class)
        self.assertIsNone(error)

    def test_clear_error_message_when_neither_sdk_available(self):
        def broken_v2():
            raise ImportError("v2 not found")

        def broken_v1():
            raise ImportError("v1 not found")

        server_class, error = mcp_server._import_mcp_server_base(import_v2=broken_v2, import_v1=broken_v1)
        self.assertIsNone(server_class)
        self.assertIsNotNone(error)
        # the message must actually explain what went wrong, not just "not installed"
        self.assertIn("MCP server class could be", error)
        self.assertIn("v2 not found", error)
        self.assertIn("v1 not found", error)

    def test_main_raises_clear_error_when_mcp_unavailable(self):
        with patch.object(mcp_server, "mcp", None), \
             patch.object(mcp_server, "_MCP_IMPORT_ERROR", "custom reason"):
            with self.assertRaises(SystemExit) as ctx:
                mcp_server.main()
            self.assertIn("custom reason", str(ctx.exception))


class TransportSelectionTests(unittest.TestCase):
    def test_defaults_to_stdio(self):
        with patch.object(mcp_server, "mcp", MagicMock()) as fake_mcp, \
             patch("sys.argv", ["inoue-mcp"]), \
             patch.dict("os.environ", {}, clear=True):
            mcp_server.main()
            fake_mcp.run.assert_called_once_with(transport="stdio")

    def test_transport_flag_selects_streamable_http(self):
        with patch.object(mcp_server, "mcp", MagicMock()) as fake_mcp, \
             patch("sys.argv", ["inoue-mcp", "--transport", "streamable-http"]):
            mcp_server.main()
            fake_mcp.run.assert_called_once_with(transport="streamable-http")

    def test_transport_env_var_is_respected(self):
        with patch.object(mcp_server, "mcp", MagicMock()) as fake_mcp, \
             patch("sys.argv", ["inoue-mcp"]), \
             patch.dict("os.environ", {"INOUE_MCP_TRANSPORT": "sse"}):
            mcp_server.main()
            fake_mcp.run.assert_called_once_with(transport="sse")

    def test_invalid_transport_is_rejected(self):
        with patch.object(mcp_server, "mcp", MagicMock()), \
             patch("sys.argv", ["inoue-mcp", "--transport", "carrier-pigeon"]):
            with self.assertRaises(SystemExit):
                mcp_server.main()


class ToolRegistrationTests(unittest.TestCase):
    @unittest.skipUnless(mcp_server.mcp is not None, "optional mcp SDK is not installed")
    def test_all_expected_tools_are_registered(self):
        import asyncio
        tools = asyncio.run(mcp_server.mcp.list_tools())
        names = {t.name for t in tools}
        self.assertEqual(names, {
            "search_catalog", "get_catalog_summary", "scan_read_only",
            "check_waf_tool", "check_security_headers_tool", "get_scan_history_tool",
        })

    @unittest.skipUnless(mcp_server.mcp is not None, "optional mcp SDK is not installed")
    def test_every_tool_has_a_docstring_description(self):
        import asyncio
        tools = asyncio.run(mcp_server.mcp.list_tools())
        for tool in tools:
            self.assertTrue(tool.description and len(tool.description) > 10, tool.name)


class CatalogToolTests(unittest.TestCase):
    def test_search_signatures_is_catalog_only_no_network(self):
        matches = search_signatures("nginx")
        self.assertTrue(len(matches) >= 1)
        for match in matches:
            self.assertIn("name", match)
            self.assertIn("category", match)

    def test_search_signatures_filters_by_category(self):
        matches = search_signatures("a", category="Web Server")
        for match in matches:
            self.assertEqual(match["category"], "Web Server")

    def test_catalog_summary_counts_match_search_results(self):
        summary = catalog_summary()
        self.assertGreater(summary["count"], 1000)
        self.assertIn("categories", summary)


class LightweightToolTests(unittest.TestCase):
    @patch("mcp_server._lightweight_fetch")
    def test_check_waf_uses_single_lightweight_fetch(self, mock_fetch):
        mock_fetch.return_value = ({"cf-ray": "abc"}, {})
        findings = check_waf("example.com")
        mock_fetch.assert_called_once()
        names = {f["name"] for f in findings}
        self.assertIn("Cloudflare", names)

    @patch("mcp_server._lightweight_fetch")
    def test_check_security_headers_returns_grade_and_cors(self, mock_fetch):
        mock_fetch.return_value = ({"strict-transport-security": "max-age=1"}, {})
        result = check_security_headers("example.com")
        self.assertIn("grade", result)
        self.assertIn("cors_misconfig", result)

    @patch("mcp_server.list_snapshots")
    def test_get_scan_history_never_triggers_a_scan(self, mock_list):
        mock_list.return_value = [{"scanned_at": 123.0, "result": {"technologies": [{"name": "Nginx"}]}}]
        with patch("mcp_server.scan") as mock_scan:
            history = get_scan_history("example.com")
            mock_scan.assert_not_called()
        self.assertEqual(history[0]["technology_count"], 1)


class ScanReadOnlyToolTests(unittest.TestCase):
    @patch("mcp_server.scan")
    def test_scan_target_includes_waf_field(self, mock_scan):
        fake_result = MagicMock()
        fake_result.final_url = "https://example.com"
        fake_result.status_code = 200
        fake_result.response_time_ms = 42.0
        fake_result.technologies = []
        fake_result.waf = [{"name": "Cloudflare"}]
        fake_result.notes = []
        fake_result.error = None
        mock_scan.return_value = fake_result

        payload = scan_target("example.com")

        self.assertEqual(payload["waf"], [{"name": "Cloudflare"}])
        mock_scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()
