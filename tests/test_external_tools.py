import unittest
from unittest.mock import MagicMock, patch

from core import external_tools as et
from core.scanner import Detection, ScanResult, _collect_external_tool_results, scan


class ToolAvailabilityTests(unittest.TestCase):
    """Every wrapper must degrade cleanly when the binary isn't on PATH."""

    @patch("core.external_tools._which", return_value=None)
    def test_subfinder_unavailable(self, _):
        result = et.run_subfinder("example.com")
        self.assertFalse(result["available"])
        self.assertIn("subfinder", result["note"])
        self.assertEqual(result["results"], [])

    @patch("core.external_tools._which", return_value=None)
    def test_naabu_unavailable(self, _):
        result = et.run_naabu("example.com")
        self.assertFalse(result["available"])

    @patch("core.external_tools._which", return_value=None)
    def test_nmap_unavailable(self, _):
        result = et.run_nmap_service_scan("example.com")
        self.assertFalse(result["available"])

    @patch("core.external_tools._which", return_value=None)
    def test_nuclei_unavailable(self, _):
        result = et.run_nuclei("https://example.com")
        self.assertFalse(result["available"])

    @patch("core.external_tools._which", return_value=None)
    def test_gau_unavailable(self, _):
        self.assertFalse(et.run_gau("example.com")["available"])

    @patch("core.external_tools._which", return_value=None)
    def test_waybackurls_unavailable(self, _):
        self.assertFalse(et.run_waybackurls("example.com")["available"])

    @patch("core.external_tools._which", return_value=None)
    def test_katana_unavailable(self, _):
        self.assertFalse(et.run_katana("https://example.com")["available"])

    @patch("core.external_tools._which", return_value=None)
    def test_gowitness_unavailable(self, _):
        self.assertFalse(et.run_gowitness("https://example.com", "/tmp/out")["available"])


class SubfinderParsingTests(unittest.TestCase):
    @patch("core.external_tools._which", return_value="/usr/local/bin/subfinder")
    @patch("core.external_tools._run")
    def test_parses_jsonl_output(self, mock_run, _):
        mock_run.return_value = (0, '{"host":"api.example.com"}\n{"host":"www.example.com"}\n', "")
        result = et.run_subfinder("example.com")
        self.assertTrue(result["available"])
        self.assertEqual(result["results"], ["api.example.com", "www.example.com"])

    @patch("core.external_tools._which", return_value="/usr/local/bin/subfinder")
    @patch("core.external_tools._run")
    def test_dedupes_hosts(self, mock_run, _):
        mock_run.return_value = (0, '{"host":"api.example.com"}\n{"host":"api.example.com"}\n', "")
        result = et.run_subfinder("example.com")
        self.assertEqual(result["results"], ["api.example.com"])

    @patch("core.external_tools._which", return_value="/usr/local/bin/subfinder")
    @patch("core.external_tools._run")
    def test_surfaces_error_when_nonzero_and_empty(self, mock_run, _):
        mock_run.return_value = (1, "", "connection refused")
        result = et.run_subfinder("example.com")
        self.assertTrue(result["available"])
        self.assertIn("connection refused", result["error"])

    @patch("core.external_tools._which", return_value="/usr/local/bin/subfinder")
    @patch("core.external_tools._run")
    def test_falls_back_to_plain_lines_without_json(self, mock_run, _):
        mock_run.return_value = (0, "api.example.com\nwww.example.com\n", "")
        result = et.run_subfinder("example.com")
        self.assertEqual(result["results"], ["api.example.com", "www.example.com"])


class NaabuParsingTests(unittest.TestCase):
    @patch("core.external_tools._which", return_value="/usr/local/bin/naabu")
    @patch("core.external_tools._run")
    def test_parses_open_ports(self, mock_run, _):
        mock_run.return_value = (0, '{"ip":"1.2.3.4","port":443}\n{"ip":"1.2.3.4","port":80}\n', "")
        result = et.run_naabu("example.com")
        ports = {p["port"] for p in result["results"]}
        self.assertEqual(ports, {443, 80})

    @patch("core.external_tools._which", return_value="/usr/local/bin/naabu")
    @patch("core.external_tools._run")
    def test_no_open_ports_is_not_an_error(self, mock_run, _):
        mock_run.return_value = (0, "", "")
        result = et.run_naabu("example.com")
        self.assertTrue(result["available"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["results"], [])


class NmapParsingTests(unittest.TestCase):
    SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="closed"/>
        <service name="http-proxy"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

    @patch("core.external_tools._which", return_value="/usr/bin/nmap")
    @patch("core.external_tools._run")
    def test_only_open_ports_are_reported(self, mock_run, _):
        mock_run.return_value = (0, self.SAMPLE_XML, "")
        result = et.run_nmap_service_scan("example.com")
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["port"], 443)
        self.assertEqual(result["results"][0]["product"], "nginx")
        self.assertEqual(result["results"][0]["version"], "1.24.0")

    @patch("core.external_tools._which", return_value="/usr/bin/nmap")
    @patch("core.external_tools._run")
    def test_malformed_xml_does_not_crash(self, mock_run, _):
        mock_run.return_value = (0, "not xml at all <<<", "")
        result = et.run_nmap_service_scan("example.com")
        self.assertTrue(result["available"])
        self.assertEqual(result["results"], [])


class ActivePortScanOrchestrationTests(unittest.TestCase):
    @patch("core.external_tools.run_nmap_service_scan")
    @patch("core.external_tools.run_naabu")
    def test_runs_nmap_on_naabu_discovered_ports(self, mock_naabu, mock_nmap):
        mock_naabu.return_value = {"tool": "naabu", "available": True, "results": [{"port": 443, "ip": "1.2.3.4"}], "error": None, "note": None}
        mock_nmap.return_value = {"tool": "nmap", "available": True, "results": [{"port": 443, "service": "https"}], "error": None, "note": None}
        result = et.active_port_scan("example.com")
        mock_nmap.assert_called_once_with("example.com", ports="443", timeout=180)
        self.assertEqual(result["services"]["results"][0]["port"], 443)

    @patch("core.external_tools.run_nmap_service_scan")
    @patch("core.external_tools.run_naabu", return_value={"tool": "naabu", "available": False, "results": [], "error": None, "note": "not found"})
    def test_falls_back_to_nmap_when_naabu_missing(self, _, mock_nmap):
        mock_nmap.return_value = {"tool": "nmap", "available": True, "results": [], "error": None, "note": None}
        result = et.active_port_scan("example.com")
        mock_nmap.assert_called_once()
        self.assertIs(result["discovery"], result["services"])


class NucleiParsingTests(unittest.TestCase):
    @patch("core.external_tools._which", return_value="/usr/local/bin/nuclei")
    @patch("core.external_tools._run")
    def test_parses_findings(self, mock_run, _):
        line = '{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium","description":"desc"},"matched-at":"https://example.com/admin"}'
        mock_run.return_value = (0, line + "\n", "")
        result = et.run_nuclei("https://example.com")
        finding = result["results"][0]
        self.assertEqual(finding["template_id"], "exposed-panel")
        self.assertEqual(finding["severity"], "medium")
        self.assertEqual(finding["matched_at"], "https://example.com/admin")

    @patch("core.external_tools._which", return_value="/usr/local/bin/nuclei")
    @patch("core.external_tools._run")
    def test_passes_severity_and_tags_flags(self, mock_run, _):
        mock_run.return_value = (0, "", "")
        et.run_nuclei("https://example.com", severity="high,critical", tags="cve")
        cmd = mock_run.call_args[0][0]
        self.assertIn("-severity", cmd)
        self.assertIn("high,critical", cmd)
        self.assertIn("-tags", cmd)
        self.assertIn("cve", cmd)

    @patch("core.external_tools._which", return_value="/usr/local/bin/nuclei")
    @patch("core.external_tools._run")
    def test_never_enables_interactsh(self, mock_run, _):
        """-ni keeps nuclei from reaching out to an interactsh server -
        this must stay passive/offline-friendly, not become an active
        exploitation channel."""
        mock_run.return_value = (0, "", "")
        et.run_nuclei("https://example.com")
        cmd = mock_run.call_args[0][0]
        self.assertIn("-ni", cmd)


class UrlHarvestingTests(unittest.TestCase):
    @patch("core.external_tools._which", return_value="/usr/local/bin/gau")
    @patch("core.external_tools._run")
    def test_gau_splits_lines(self, mock_run, _):
        mock_run.return_value = (0, "https://example.com/a\nhttps://example.com/b\n", "")
        result = et.run_gau("example.com")
        self.assertEqual(result["results"], ["https://example.com/a", "https://example.com/b"])

    @patch("core.external_tools.run_katana")
    @patch("core.external_tools.run_waybackurls")
    @patch("core.external_tools.run_gau")
    def test_harvest_urls_merges_and_dedupes_across_tools(self, mock_gau, mock_wayback, mock_katana):
        mock_gau.return_value = {"tool": "gau", "available": True, "results": ["https://example.com/a", "https://example.com/shared"], "error": None, "note": None}
        mock_wayback.return_value = {"tool": "waybackurls", "available": True, "results": ["https://example.com/shared", "https://example.com/b"], "error": None, "note": None}
        mock_katana.return_value = {"tool": "katana", "available": True, "results": ["https://example.com/c"], "error": None, "note": None}
        merged = et.harvest_urls("example.com", "https://example.com")
        self.assertEqual(merged["merged_count"], 4)
        self.assertEqual(
            set(merged["merged_urls"]),
            {"https://example.com/a", "https://example.com/b", "https://example.com/c", "https://example.com/shared"},
        )


class ScannerWiringTests(unittest.TestCase):
    """Confirms the recon-task results actually land in ScanResult.enriched."""

    def test_collect_external_tool_results_maps_task_keys_to_output_keys(self):
        recon_results = {
            "ext_subdomains": {"tool": "subfinder", "available": True, "results": ["a.example.com"]},
            "ext_nuclei": {"tool": "nuclei", "available": True, "results": []},
            "dns": {"A": ["1.2.3.4"]},  # unrelated task, must be ignored
        }
        collected = _collect_external_tool_results(recon_results)
        self.assertEqual(set(collected.keys()), {"active_subdomains", "nuclei"})
        self.assertEqual(collected["active_subdomains"]["results"], ["a.example.com"])

    def test_collect_external_tool_results_empty_when_nothing_ran(self):
        self.assertEqual(_collect_external_tool_results({"dns": {}}), {})

    @patch("core.external_tools.run_subfinder")
    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_wires_active_subdomains_into_enriched(self, mock_get, mock_subfinder):
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {"server": "nginx"}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response
        mock_subfinder.return_value = {"tool": "subfinder", "available": True, "results": ["api.example.com"], "error": None, "note": None}

        result = scan("https://example.com", modules=["fast"], active_subdomains=True)

        mock_subfinder.assert_called_once()
        self.assertEqual(
            result.enriched["external_tools"]["active_subdomains"]["results"],
            ["api.example.com"],
        )

    @patch("core.external_tools.run_subfinder")
    @patch("core.scanner._get_with_redirect_policy")
    def test_scan_skips_external_tools_when_flags_are_off(self, mock_get, mock_subfinder):
        fake_response = MagicMock()
        fake_response.url = "https://example.com/"
        fake_response.status_code = 200
        fake_response.headers = {"server": "nginx"}
        fake_response.cookies.items.return_value = []
        fake_response.text = "<html></html>"
        mock_get.return_value = fake_response

        result = scan("https://example.com", modules=["fast"])

        mock_subfinder.assert_not_called()
        self.assertNotIn("external_tools", result.enriched)


if __name__ == "__main__":
    unittest.main()
