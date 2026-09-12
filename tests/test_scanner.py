import asyncio
import json
import re
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from core.cache import ScanCache
from core.scanner import (
    Detection,
    ScanResult,
    _get_whois,
    _get_rdap_details,
    _extract_deep_version,
    _header_value,
    _normalize_version,
    _parse_cert_datetime,
    _serialize_scan_result,
    _deserialize_scan_result,
    _scan_cache_module,
    _async_scan_target,
    scan,
    async_scan_many,
    build_recon_plan,
    build_service_summary,
    detect_contradictions,
    merge_subdomain_candidates,
    summarize_whois_details,
    run_fingerprints,
)
from core.cve import correlate_cves, refresh_cve_dataset
from core.config import load_config
from core.plugins import run_plugins
from fingerprints.signatures import SIGNATURES
from inoue import app, format_update_report, load_targets, render_html_report, result_exit_code, result_to_dict, write_nuclei_export


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

    def test_run_fingerprints_can_limit_detection_to_headers(self):
        detections = run_fingerprints(
            {"Server": "nginx/1.26.1"},
            {},
            '<meta name="generator" content="WordPress 6.4.2">',
            sources={"headers"},
        )

        names = {item.name for item in detections}
        self.assertIn("Nginx", names)
        self.assertNotIn("WordPress", names)

    def test_header_matching_is_case_insensitive(self):
        detections = run_fingerprints(
            {"sErVeR": "nginx/1.26.1"},
            {},
            "",
            sources={"headers"},
        )

        detected = {item.name: item for item in detections}
        self.assertEqual(detected["Nginx"].version, "1.26.1")
        self.assertEqual(_header_value({"X-Test": "value"}, "x-test"), "value")

    def test_normalize_version_rejects_timestamp_like_strings(self):
        for value in [
            "1789011933767.02",
            "6.17890119937",
            "1789012125429.63156",
            "5.1789012131349.13281",
            "bom1::iad1::abc-1789011933767-3f7a9d",
        ]:
            self.assertIsNone(_normalize_version(value))

    def test_deep_version_extraction_supports_assets_metadata_and_releases(self):
        self.assertEqual(_extract_deep_version("/assets/app.js?ver=3.23.0"), "3.23.0")
        self.assertEqual(_extract_deep_version('data-version="6.4.2"'), "6.4.2")
        self.assertEqual(_extract_deep_version("release: 2024.10.3"), "2024.10.3")
        self.assertEqual(_extract_deep_version("/static/framework-v2.7.1.min.js"), "2.7.1")

    def test_parse_cert_datetime_handles_gmt_and_iso_variants(self):
        self.assertEqual(_parse_cert_datetime("Sep 10 19:27:31 2026 GMT"), "2026-09-10T19:27:31Z")
        self.assertEqual(_parse_cert_datetime("2026-09-10T19:27:31Z"), "2026-09-10T19:27:31Z")
        self.assertIsNone(_parse_cert_datetime("not-a-date"))

    def test_parse_cert_datetime_preserves_iso_values_and_strips_empty_values(self):
        self.assertEqual(_parse_cert_datetime("2026-09-10T19:27:31Z"), "2026-09-10T19:27:31Z")
        self.assertIsNone(_parse_cert_datetime("   "))

    def test_ubuntu_signature_requires_header_context_not_meta_description(self):
        html = '<meta name="description" content="Interactive Ubuntu-style desktop portfolio">'
        detections = run_fingerprints({}, {}, html)
        self.assertNotIn("Ubuntu", {item.name for item in detections})

    def test_whois_failures_are_structured_and_not_raw_stderr(self):
        with patch("core.scanner.whois") as mock_whois:
            mock_whois.whois.side_effect = RuntimeError("No address associated with hostname")
            result = _get_whois("example.invalid")
        self.assertIn("error", result)
        self.assertIn("No address associated with hostname", result["error"])

    @patch("core.scanner.httpx.Client")
    def test_rdap_details_are_structured_and_json_safe(self, mock_client):
        response = MagicMock(status_code=200)
        response.json.return_value = {
            "handle": "EXAMPLE",
            "ldhName": "example.com",
            "status": ["active"],
            "events": [{"eventAction": "registration", "eventDate": "2024-01-01T00:00:00Z"}],
            "nameservers": [{"ldhName": "ns1.example.com"}],
            "entities": [{"handle": "REG-1", "roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
        }
        mock_client.return_value.__enter__.return_value.get.return_value = response

        details = _get_rdap_details("example.com")

        self.assertEqual(details["ldh_name"], "example.com")
        self.assertEqual(details["events"]["registration"], "2024-01-01T00:00:00Z")
        self.assertEqual(details["nameservers"], ["ns1.example.com"])
        self.assertEqual(details["entities"][0]["fn"], "Example Registrar")

    def test_plugin_non_serializable_output_becomes_structured_error(self):
        with TemporaryDirectory() as temp_dir:
            plugin_path = Path(temp_dir) / "broken_plugin.py"
            plugin_path.write_text("def run(result):\n    return {1, 2, 3}\n", encoding="utf-8")
            result = ScanResult("https://example.com", "https://example.com", 200, 1)

            outputs = run_plugins(result, [temp_dir])

        self.assertIn("error", outputs["broken_plugin"])

    def test_cache_hit_marks_cached_scan_in_result(self):
        with TemporaryDirectory() as temp_dir:
            cache_path = str(Path(temp_dir) / "cache.db")

            async def run_once():
                return await async_scan_many(["example.com"], workers=1, cache_path=cache_path, progress=lambda msg: None)

            first = asyncio.run(run_once())
            second = asyncio.run(run_once())

        self.assertFalse(first[0].cache_hit)
        self.assertTrue(second[0].cache_hit)

    def test_cache_round_trip_preserves_recon_fields(self):
        result = ScanResult(
            url="https://example.com",
            final_url="https://example.com/",
            status_code=200,
            response_time_ms=12.3,
            dns_records={"A": ["192.0.2.1"]},
            whois_info={"domain_name": "example.com"},
            whois_summary={"domain": "example.com"},
            subdomains=["api.example.com"],
            mail_records=["mail.example.com"],
            open_ports=[{"port": 443, "service": "https"}],
            directories=[{"path": "/admin", "status_code": 403}],
            extra_intel={"title": "Example"},
        )

        restored = _deserialize_scan_result(_serialize_scan_result(result))

        self.assertEqual(restored.dns_records, result.dns_records)
        self.assertEqual(restored.whois_info, result.whois_info)
        self.assertEqual(restored.whois_summary, result.whois_summary)
        self.assertEqual(restored.subdomains, result.subdomains)
        self.assertEqual(restored.mail_records, result.mail_records)
        self.assertEqual(restored.open_ports, result.open_ports)
        self.assertEqual(restored.directories, result.directories)
        self.assertEqual(restored.extra_intel, result.extra_intel)

    def test_cache_closes_database_connections_on_cleanup(self):
        with TemporaryDirectory() as temp_dir:
            cache_path = str(Path(temp_dir) / "cache.db")
            cache = ScanCache(cache_path)
            cache.close()
            self.assertIsNone(cache._connection)

    def test_cache_key_changes_with_scan_configuration(self):
        fast_key = _scan_cache_module(10, True, True, True, ["fast"], None, None, None)
        full_key = _scan_cache_module(10, True, True, True, ["full-recon"], None, None, None)

        self.assertNotEqual(fast_key, full_key)

    def test_async_full_recon_populates_selected_modules(self):
        response = MagicMock()
        response.url = "https://example.com/"
        response.status_code = 200
        response.headers = {"server": "nginx"}
        response.cookies.items.return_value = []
        response.text = "<html><title>Example</title></html>"
        client = MagicMock()
        client.get = AsyncMock(return_value=response)

        with patch("core.scanner._get_dns", return_value={"A": ["192.0.2.1"]}), \
             patch("core.scanner._get_ssl_info", return_value={"available": True}), \
             patch("core.scanner._get_whois", return_value={"domain_name": "example.com"}), \
             patch("core.scanner._get_mail_records", return_value=["mail.example.com"]), \
             patch("core.scanner.discover_subdomains", return_value=["api.example.com"]), \
             patch("core.scanner._scan_common_ports", return_value=[{"port": 443}]), \
             patch("core.scanner._enumerate_directories", return_value=[{"path": "/admin"}]), \
             patch("core.scanner._fetch_public_intel", return_value={"source": "test"}):
            result = asyncio.run(_async_scan_target(
                client,
                "https://example.com",
                5,
                True,
                ["full-recon"],
            ))

        self.assertEqual(result.dns_records, {"A": ["192.0.2.1"]})
        self.assertEqual(result.whois_info["domain_name"], "example.com")
        self.assertEqual(result.mail_records, ["mail.example.com"])
        self.assertEqual(result.subdomains, ["api.example.com"])
        self.assertEqual(result.open_ports, [{"port": 443}])
        self.assertEqual(result.directories, [{"path": "/admin"}])

    def test_redirected_scan_uses_final_url_for_detection_and_ip(self):
        response = MagicMock()
        response.url = "https://destination.example/wp-admin"
        response.status_code = 200
        response.headers = {}
        response.cookies.items.return_value = []
        response.text = ""
        client = MagicMock()
        client.__enter__.return_value = client
        client.__exit__.return_value = None
        client.get.return_value = response

        with patch("core.scanner.httpx.Client", return_value=client), patch(
            "core.scanner._resolve_ip", return_value="192.0.2.44"
        ) as resolve_ip:
            result = scan("https://source.example")

        self.assertIn("WordPress", {item.name for item in result.technologies})
        resolve_ip.assert_called_once_with("destination.example")
        self.assertEqual(result.ip, "192.0.2.44")

    def test_markdown_and_html_output_files_are_renders_not_json(self):
        result = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=42,
            technologies=[
                Detection("Nginx", "Web Server", version="1.26.0", confidence="high", evidence="Server: nginx"),
                Detection("WordPress", "CMS", version="6.4.0", confidence="medium", evidence="meta generator"),
            ],
        )

        markdown = render_html_report([result])
        self.assertIn("<html", markdown.lower())
        self.assertIn("Inoue reconnaissance report", markdown)
        self.assertNotIn("\"technologies\"", markdown)

        markdown_report = __import__("inoue").render_markdown_report([result])
        self.assertIn("# Inoue reconnaissance report", markdown_report)
        self.assertIn("| Target | Technology |", markdown_report)
        self.assertNotIn("\"technologies\"", markdown_report)

    def test_cli_output_files_in_markdown_and_html_are_rendered_not_raw_json(self):
        runner = CliRunner()
        with TemporaryDirectory() as temp_dir:
            md_path = Path(temp_dir) / "report.md"
            html_path = Path(temp_dir) / "report.html"

            runner.invoke(app, ["--no-banner", "--json", "--output", str(md_path), "example.com"], catch_exceptions=False)
            runner.invoke(app, ["--no-banner", "--json", "--output", str(html_path), "example.com"], catch_exceptions=False)

            md_text = md_path.read_text(encoding="utf-8")
            html_text = html_path.read_text(encoding="utf-8")

        self.assertIn("# Inoue reconnaissance report", md_text)
        self.assertNotIn("\"technologies\"", md_text)
        self.assertIn("<html", html_text.lower())
        self.assertIn("Inoue reconnaissance report", html_text)
        self.assertNotIn("\"technologies\"", html_text)

    def test_run_fingerprints_detects_deeper_service_signatures(self):
        headers = {"Server": "Apache/2.4.49"}
        body = '<meta name="generator" content="Jenkins 2.440"><script src="/static/jenkins.js"></script>'

        detections = run_fingerprints(headers, {}, body)
        names = {d.name for d in detections}

        self.assertIn("Apache", names)
        self.assertIn("Jenkins", names)

    def test_run_fingerprints_detects_curated_application_server_headers(self):
        detections = run_fingerprints(
            {"Server": "Kestrel", "X-Powered-By": "Node.js/22.1.0"},
            {},
            "",
        )
        detected = {item.name: item for item in detections}

        self.assertIn("Kestrel", detected)
        self.assertIn("Node.js HTTP", detected)
        self.assertEqual(detected["Node.js HTTP"].version, "22.1.0")

    def test_web_server_catalog_has_at_least_forty_curated_entries(self):
        web_server_categories = {
            "Web Server", "Application Server", "Proxy", "Reverse Proxy"
        }
        curated_names = [
            name for name, signature in SIGNATURES.items()
            if signature.get("category") in web_server_categories
        ]

        self.assertGreaterEqual(len(curated_names), 40)

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

    @patch("inoue.scan")
    def test_cli_headers_flag_renders_headers_without_verbose(self, mock_scan):
        mock_scan.return_value = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=200,
            response_time_ms=1,
            headers={"strict-transport-security": "max-age=31536000"},
        )

        result = CliRunner().invoke(app, ["--headers", "--no-banner", "example.com"], catch_exceptions=False)

        self.assertEqual(result.exit_code, 0)
        self.assertIn("security headers", result.stdout)
        self.assertIn("Strict-Transport-Security", result.stdout)

    def test_result_to_dict_preserves_all_recon_fields(self):
        result = ScanResult(
            url="https://example.com",
            final_url="https://example.com/",
            status_code=200,
            response_time_ms=1,
            headers={"server": "nginx"},
            whois_info={"domain_name": "example.com"},
            whois_summary={"domain": "example.com"},
            subdomains=["api.example.com"],
            mail_records=["mail.example.com"],
            open_ports=[{"port": 443, "service": "https"}],
            directories=[{"path": "/admin", "status_code": 403, "source": "active"}],
            extra_intel={"title": "Example"},
        )

        payload = result_to_dict(result)

        self.assertEqual(payload["headers"], result.headers)
        self.assertEqual(payload["whois"], result.whois_info)
        self.assertEqual(payload["subdomains"], result.subdomains)
        self.assertEqual(payload["mail_records"], result.mail_records)
        self.assertEqual(payload["open_ports"], result.open_ports)
        self.assertEqual(payload["directories"], result.directories)
        self.assertEqual(payload["extra_intel"], result.extra_intel)

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

    def test_config_uses_project_values_over_user_values(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            user_path = root / "user.toml"
            project_path = root / "project.toml"
            user_path.write_text("rate_limit = 2\ncache = true\n", encoding="utf-8")
            project_path.write_text("rate_limit = 1\n", encoding="utf-8")

            config = load_config(str(project_path), str(user_path))

        self.assertEqual(config["rate_limit"], 1)
        self.assertTrue(config["cache"])

    def test_semantic_exit_codes_distinguish_errors_and_cves(self):
        clean = ScanResult("https://clean.example", "https://clean.example", 200, 1)
        error = ScanResult("https://error.example", "https://error.example", 0, 1, error="timeout")
        cve_result = ScanResult(
            "https://vulnerable.example",
            "https://vulnerable.example",
            200,
            1,
            technologies=[Detection("Apache", "Web Server", cves=[{"id": "CVE-TEST"}])],
        )

        self.assertEqual(result_exit_code([clean], False, False), 0)
        self.assertEqual(result_exit_code([error], False, False), 1)
        self.assertEqual(result_exit_code([cve_result], True, True), 2)
        self.assertEqual(result_exit_code([cve_result], True, False), 0)

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
