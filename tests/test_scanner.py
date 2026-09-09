import asyncio
import json
import re
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from core.scanner import (
    Detection,
    ScanResult,
    async_scan_many,
    build_recon_plan,
    build_service_summary,
    detect_contradictions,
    merge_subdomain_candidates,
    summarize_whois_details,
    run_fingerprints,
)
from core.cve import correlate_cves, refresh_cve_dataset
from core.plugins import run_plugins
from fingerprints.signatures import SIGNATURES
from inoue import app, format_update_report, load_targets, render_html_report, write_nuclei_export


class ScannerSummaryTests(unittest.TestCase):
    def test_build_service_summary_lists_services_with_versions_and_confidence(self):
        result = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=120.5,
            technologies=[
                Detection(name="Nginx", category="Web Server", version="1.26.0", confidence="high", evidence="Server: nginx"),
                Detection(name="WordPress", category="CMS", version="6.5", confidence="medium", evidence="Meta generator"),
            ],
        )

        summary = build_service_summary(result)

        self.assertEqual(len(summary), 2)
        self.assertEqual(summary[0]["name"], "Nginx")
        self.assertEqual(summary[0]["version"], "1.26.0")
        self.assertEqual(summary[0]["confidence"], "high")
        self.assertIn("WordPress", [item["name"] for item in summary])

    def test_run_fingerprints_detects_services_and_versions(self):
        headers = {"Server": "nginx/1.26.1", "X-Powered-By": "PHP/8.1.2"}
        body = '<meta name="generator" content="WordPress 6.4.2"><script src="/wp-content/themes/twentytwentyfour/style.css"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Nginx", names)
        self.assertIn("PHP", names)
        self.assertIn("WordPress", names)
        self.assertEqual(next(d.version for d in detections if d.name == "Nginx"), "1.26.1")

    def test_run_fingerprints_detects_deeper_service_signatures(self):
        headers = {"Server": "Apache/2.4.49"}
        body = '<meta name="generator" content="Jenkins 2.440"><script src="/static/jenkins.js"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Apache", names)
        self.assertIn("Jenkins", names)

    def test_run_fingerprints_detects_services_from_url_path(self):
        headers = {}
        body = ""

        detections = run_fingerprints(headers, {}, body, url="https://target.example/phpmyadmin/index.php")
        names = {d.name for d in detections}

        self.assertIn("phpMyAdmin", names)

    def test_run_fingerprints_detects_api_routes_and_docs(self):
        headers = {}
        body = ""

        graphql = run_fingerprints(headers, {}, body, url="https://target.example/graphql")
        self.assertIn("GraphQL", {d.name for d in graphql})

        swagger = run_fingerprints(headers, {}, body, url="https://target.example/swagger-ui/index.html")
        self.assertIn("Swagger UI", {d.name for d in swagger})

        openapi = run_fingerprints(headers, {}, body, url="https://target.example/openapi.json")
        self.assertIn("OpenAPI", {d.name for d in openapi})

    def test_run_fingerprints_detects_wordpress_plugin_signatures(self):
        headers = {}
        body = '<link rel="stylesheet" href="/wp-content/plugins/elementor/assets/css/frontend.min.css">'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Elementor", names)

    def test_run_fingerprints_detects_payment_gateway_signatures(self):
        headers = {}
        body = '<script src="https://js.stripe.com/v3"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Stripe", names)

    def test_run_fingerprints_detects_inline_source_code_signatures(self):
        headers = {}
        body = '<script>Sentry.init({dsn:"https://example@sentry.io/123"});</script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Sentry", names)

    def test_run_fingerprints_extracts_versions_from_html_and_scripts(self):
        headers = {}
        body = '<meta name="generator" content="WordPress 6.5.1"><script src="/wp-content/plugins/elementor/assets/js/frontend.min.js?v=3.23.0"></script>'

        detections = run_fingerprints(headers, {}, body)
        versions = {d.name: d.version for d in detections if d.version}

        self.assertEqual(versions.get("WordPress"), "6.5.1")
        self.assertEqual(versions.get("Elementor"), "3.23.0")

    def test_confidence_score_rewards_independent_html_agreement(self):
        html_name = "__confidence_html_fixture__"
        script_name = "__confidence_script_fixture__"
        html_signature = {
            "category": "Test",
            "html": [re.compile(r"html-signal-one"), re.compile(r"html-signal-two"), re.compile(r"html-signal-three")],
        }
        script_signature = {"category": "Test", "scripts": [re.compile(r"script-signal")]}
        with patch.dict(
            "core.scanner.COMPILED_SIGNATURES",
            {html_name: html_signature, script_name: script_signature},
            clear=False,
        ), patch("core.scanner._collect_candidate_signatures", return_value={html_name, script_name}):
            detections = run_fingerprints(
                {},
                {},
                '<script src="/script-signal.js"></script> html-signal-one html-signal-two html-signal-three',
            )

        scores = {d.name: d.confidence_score for d in detections}
        self.assertGreater(scores[html_name], scores[script_name])
        self.assertGreater(scores[html_name], 0)

    def test_negative_signature_excludes_generic_detection(self):
        generic_name = "__generic_fixture__"
        specific_name = "__specific_fixture__"
        with patch.dict(
            "core.scanner.COMPILED_SIGNATURES",
            {
                generic_name: {"category": "Test", "html": [re.compile(r"shared-signal")], "excludes": [specific_name]},
                specific_name: {"category": "Test", "html": [re.compile(r"shared-signal")]},
            },
            clear=False,
        ), patch("core.scanner._collect_candidate_signatures", return_value={generic_name, specific_name}):
            detections = run_fingerprints({}, {}, "shared-signal")

        self.assertEqual({d.name for d in detections}, {specific_name})

    def test_contradictions_flag_conflicting_server_signals(self):
        detections = [
            Detection("Nginx", "Web Server", evidence="Server: nginx"),
            Detection("Apache", "Web Server", evidence="HTML: Apache"),
        ]

        notes = detect_contradictions(detections)

        self.assertEqual(len(notes), 1)
        self.assertIn("nginx", notes[0].lower())
        self.assertIn("apache", notes[0].lower())

    def test_run_fingerprints_detects_ecommerce_and_marketing_signatures(self):
        headers = {}
        body = '<script src="https://js.stripe.com/v3"></script><script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script><script src="https://js.hs-scripts.com/123456.js"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Stripe", names)
        self.assertIn("Google Analytics", names)
        self.assertIn("HubSpot", names)

    def test_signature_catalog_contains_large_cloud_and_ics_catalog(self):
        self.assertGreaterEqual(len(SIGNATURES), 5000)
        self.assertIn("OpenStack Horizon", SIGNATURES)
        self.assertIn("ScadaBR", SIGNATURES)
        self.assertIn("Cloudflare Dashboard", SIGNATURES)
        self.assertIn("Akamai Control Center", SIGNATURES)

    def test_run_fingerprints_detects_broader_service_families(self):
        headers = {}
        body = '<html><body><h1>OpenStack Horizon</h1><script src="/static/novnc.js"></script></body></html>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("OpenStack Horizon", names)
        self.assertIn("OpenStack Nova", names)

    def test_build_recon_plan_defaults_to_fast_mode(self):
        plan = build_recon_plan(None)

        self.assertTrue(plan["headers"])
        self.assertTrue(plan["tech"])
        self.assertFalse(plan["dns"])
        self.assertFalse(plan["ssl"])
        self.assertFalse(plan["whois"])
        self.assertFalse(plan["subdomains"])
        self.assertFalse(plan["mail"])
        self.assertFalse(plan["ports"])
        self.assertFalse(plan["extra"])

    def test_build_recon_plan_supports_requested_modules(self):
        plan = build_recon_plan(["dns", "ssl", "mail", "subdomains", "whois", "headers", "tech"])

        self.assertTrue(plan["dns"])
        self.assertTrue(plan["ssl"])
        self.assertTrue(plan["mail"])
        self.assertTrue(plan["subdomains"])
        self.assertTrue(plan["whois"])
        self.assertTrue(plan["headers"])
        self.assertTrue(plan["tech"])

    def test_build_recon_plan_supports_full_recon_preset(self):
        plan = build_recon_plan(["full-recon"])

        self.assertTrue(plan["dns"])
        self.assertTrue(plan["ssl"])
        self.assertTrue(plan["whois"])
        self.assertTrue(plan["subdomains"])
        self.assertTrue(plan["mail"])
        self.assertTrue(plan["tech"])
        self.assertTrue(plan["ports"])
        self.assertTrue(plan["extra"])

    def test_build_recon_plan_supports_fast_preset(self):
        plan = build_recon_plan(["fast"])

        self.assertTrue(plan["headers"])
        self.assertTrue(plan["tech"])
        self.assertFalse(plan["dns"])
        self.assertFalse(plan["ssl"])
        self.assertFalse(plan["whois"])
        self.assertFalse(plan["subdomains"])
        self.assertFalse(plan["mail"])
        self.assertFalse(plan["ports"])
        self.assertFalse(plan["extra"])

    @patch("inoue.scan")
    def test_cli_scan_passes_correct_named_arguments(self, mock_scan):
        mock_scan.return_value = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=0,
        )
        runner = CliRunner()
        result = runner.invoke(app, ["-v", "-e", "example.com"], catch_exceptions=False)

        self.assertEqual(result.exit_code, 0)
        self.assertTrue(mock_scan.called)
        _, kwargs = mock_scan.call_args
        self.assertIn("progress", kwargs)
        self.assertEqual(kwargs["api_key"], None)
        self.assertEqual(kwargs["modules"], None)

    @patch("inoue.scan")
    def test_cli_json_output_contains_only_json(self, mock_scan):
        mock_scan.return_value = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=1,
        )

        result = CliRunner().invoke(app, ["--json", "--no-banner", "example.com"], catch_exceptions=False)

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(json.loads(result.stdout)[0]["url"], "https://example.com")

    def test_summarize_whois_details_includes_company_and_contacts(self):
        summary = summarize_whois_details({
            "domain_name": "example.com",
            "organization": "Example Corp",
            "registrant": "Jane Doe",
            "registrant_country": "US",
            "registrar": "Example Registrar",
            "creation_date": ["2024-01-01"],
            "expiration_date": ["2030-01-01"],
            "name_servers": ["ns1.example.com", "ns2.example.com"],
        })

        self.assertEqual(summary["domain"], "example.com")
        self.assertEqual(summary["company"], "Example Corp")
        self.assertEqual(summary["registrant"], "Jane Doe")
        self.assertEqual(summary["country"], "US")
        self.assertIn("Example Registrar", summary["registrar"])
        self.assertEqual(summary["nameservers"], ["ns1.example.com", "ns2.example.com"])

    @patch("core.scanner.scan")
    def test_async_scan_many_scans_multiple_targets(self, mock_scan):
        mock_scan.side_effect = [
            ScanResult(
                url="https://example.com",
                final_url="https://example.com",
                status_code=200,
                response_time_ms=10,
            ),
            ScanResult(
                url="https://example.org",
                final_url="https://example.org",
                status_code=200,
                response_time_ms=20,
            ),
        ]

        async def run_scan():
            return await async_scan_many(["example.com", "example.org"], workers=2)

        results = asyncio.run(run_scan())

        self.assertEqual(len(results), 2)
        self.assertEqual([result.url for result in results], ["https://example.com", "https://example.org"])

    def test_load_targets_supports_file_and_stdin_input(self):
        with TemporaryDirectory() as temp_dir:
            target_file = Path(temp_dir) / "targets.txt"
            target_file.write_text("example.com\n# comment\nexample.org\nexample.com\n", encoding="utf-8")
            self.assertEqual(load_targets([], str(target_file)), ["example.com", "example.org"])

        stdin = StringIO("example.net\n\nexample.io\n")
        with patch("inoue.sys.stdin", stdin):
            self.assertEqual(load_targets([], None), ["example.net", "example.io"])

    @patch("core.scanner._async_scan_target", new_callable=AsyncMock)
    @patch("core.scanner.asyncio.sleep", new_callable=AsyncMock)
    def test_scan_many_rate_limits_per_host(self, mock_sleep, mock_scan_target):
        mock_scan_target.side_effect = [
            ScanResult("https://example.com/a", "https://example.com/a", 200, 1),
            ScanResult("https://example.com/b", "https://example.com/b", 200, 1),
            ScanResult("https://example.org", "https://example.org", 200, 1),
        ]

        async def run_scan():
            return await async_scan_many(
                ["https://example.com/a", "https://example.com/b", "https://example.org"],
                workers=3,
                rate_limit=1,
            )

        asyncio.run(run_scan())

        self.assertEqual(mock_sleep.await_count, 1)
        self.assertAlmostEqual(mock_sleep.await_args.args[0], 1, delta=0.1)

    @patch("core.scanner._async_scan_target", new_callable=AsyncMock)
    def test_scan_many_uses_opt_in_cache(self, mock_scan_target):
        mock_scan_target.return_value = ScanResult("example.com", "https://example.com", 200, 1)
        messages = []

        async def run_scan(cache_path):
            return await async_scan_many(
                ["example.com"],
                cache_path=cache_path,
                progress=messages.append,
            )

        with TemporaryDirectory() as temp_dir:
            cache_path = str(Path(temp_dir) / "cache.db")
            asyncio.run(run_scan(cache_path))
            asyncio.run(run_scan(cache_path))

        self.assertEqual(mock_scan_target.await_count, 1)
        self.assertIn("using cached scan", " ".join(messages))

    def test_cve_correlation_matches_exact_technology_version(self):
        matches = correlate_cves(
            "Apache",
            "2.4.49",
            [{
                "id": "CVE-2021-41773",
                "technology": "Apache",
                "version": "2.4.49",
                "summary": "Path traversal",
                "severity": "critical",
            }],
        )

        self.assertEqual(matches[0]["id"], "CVE-2021-41773")
        self.assertEqual(matches[0]["severity"], "critical")

    def test_cve_range_matching_and_severity_filtering(self):
        dataset = [
            {"id": "CVE-RANGE", "technology": "Apache", "affected": ">=2.4.0,<2.4.52", "severity": "high"},
            {"id": "CVE-LOW", "technology": "Apache", "versions": ["2.4.49"], "severity": "low"},
        ]

        in_range = correlate_cves("Apache", "2.4.49", dataset, min_severity="medium")
        boundary = correlate_cves("Apache", "2.4.52", dataset)
        exact = correlate_cves("Apache", "2.4.49", dataset)

        self.assertEqual([item["id"] for item in in_range], ["CVE-RANGE"])
        self.assertEqual(boundary, [])  # Changed to assert that boundary is empty
        self.assertEqual([item["id"] for item in exact], ["CVE-RANGE", "CVE-LOW"])

    def test_nuclei_export_groups_targets_by_technology_tag(self):
        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "nuclei.json"
            write_nuclei_export([
                ScanResult(
                    "https://example.com",
                    "https://example.com",
                    200,
                    1,
                    technologies=[Detection("Apache", "Web Server")],
                ),
            ], str(output_path))

            payload = output_path.read_text(encoding="utf-8")

        self.assertIn('"apache": [', payload)
        self.assertIn("https://example.com", payload)

    def test_html_report_contains_technology_and_cve_sections(self):
        result = ScanResult(
            "https://example.com",
            "https://example.com",
            200,
            1,
            technologies=[
                Detection(
                    "Apache",
                    "Web Server",
                    version="2.4.49",
                    confidence_score=80,
                    cves=[{"id": "CVE-TEST", "severity": "high", "summary": "Example"}],
                ),
            ],
        )

        report = render_html_report([result])

        self.assertIn("Inoue reconnaissance report", report)
        self.assertIn("Apache", report)
        self.assertIn("CVE-TEST", report)

    def test_plugins_run_and_failures_are_isolated(self):
        with TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            (plugin_dir / "working.py").write_text(
                "def run(result):\n    return {'ok': result.final_url}\n",
                encoding="utf-8",
            )
            (plugin_dir / "broken.py").write_text(
                "def run(result):\n    raise RuntimeError('plugin failed')\n",
                encoding="utf-8",
            )
            result = ScanResult("https://example.com", "https://example.com", 200, 1)
            outputs = run_plugins(result, [plugin_dir])

        self.assertEqual(outputs["working"]["ok"], "https://example.com")
        self.assertIn("plugin failed", outputs["broken"]["error"])

    @patch("core.cve.httpx.Client")
    def test_refresh_cve_dataset_writes_nvd_fixture_without_live_network(self, mock_client):
        response = MagicMock()
        response.content = b'{"vulnerabilities": [{"cve": {"id": "CVE-TEST", "descriptions": [{"lang": "en", "value": "Example"}], "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]}, "configurations": {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}}}]}'
        mock_client.return_value.__enter__.return_value.get.return_value = response

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "cves.json"
            count = refresh_cve_dataset("https://feed.example/cves.json", str(output_path))
            payload = output_path.read_text(encoding="utf-8")

        self.assertEqual(count, 1)
        self.assertIn("CVE-TEST", payload)
        mock_client.assert_called_once_with(timeout=60, verify=True, follow_redirects=True)

    def test_merge_subdomain_candidates_combines_passive_and_active_sources(self):
        merged = merge_subdomain_candidates(
            ["www.example.com", "api.example.com"],
            ["mail.example.com", "www.example.com", "dev.example.com"],
        )

        self.assertEqual(merged, ["api.example.com", "dev.example.com", "mail.example.com", "www.example.com"])

    def test_format_update_report_includes_recent_commit_details(self):
        report = format_update_report(
            fetch_output="From origin\n fetch completed",
            pull_output="Already up to date.",
            log_output="34d08b2 details\n592ed62 Create TEST",
            latest_commit_output="34d08b2 details\n core/scanner.py",
            changed_files_output="core/scanner.py\nREADME.md",
            status_output="",
        )

        self.assertIn("Already up to date", report)
        self.assertIn("Recent commits", report)
        self.assertIn("core/scanner.py", report)


if __name__ == "__main__":
    unittest.main()
