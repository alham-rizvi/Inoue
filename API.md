# Inoue API

The optional API surface is available when the FastAPI dependencies are installed.

## Health check

```bash
curl http://localhost:8000/health
```

## List signature names

```bash
curl http://localhost:8000/signatures
```

## Single scan

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://alhamrizvi.in","modules":["headers","tech"]}'
```

Request detailed WHOIS and RDAP data for a domain:

```bash
curl -sS -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://alhamrizvi.in","modules":["whois"]}' \
  | python -m json.tool
```

The response includes `whois`, `whois_summary`, and, when RDAP is available,
`whois.rdap` with domain status, lifecycle events, registrar/contact entities,
nameservers, DNSSEC data, the source URL, and the raw RDAP response. The
lookup uses the local WHOIS client plus the public standards-based RDAP
service; no API key is required.

Both `/scan` and `/scan/batch` accept the same optional flags the CLI does -
`crawl_pages`, `crawl_katana`, `js_intel`/`js_intel_bundles`,
`active_subdomains`, `active_ports`, `nuclei_scan`/`nuclei_severity`,
`harvest_urls`, `screenshot`/`screenshot_dir`, `check_takeover`,
`api_discovery`, `email_security`, `http_methods`, `save_history`, and
`scope_file` (a server-side path to a scope file; the target is refused
before any request if it isn't in scope). All default to off/unrestricted
except where noted. For example, a full posture pass:

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://alhamrizvi.in","modules":["fast"],"email_security":true,"http_methods":true,"check_takeover":true}'
```

The response now also includes `waf`, `security_grade`, `cors_misconfig`,
`http_posture`, `email_security`, `js_intel`, `takeover_candidates`,
`api_surface`, `eol_technologies`, and `risk` (the triage score combining
every signal - see COMMANDS.md's "Triage scoring" section).

## Batch scan

```bash
curl -X POST http://localhost:8000/scan/batch \
  -H 'Content-Type: application/json' \
  -d '{"targets":["https://alhamrizvi.in","https://example.org"],"workers":2}'
```

Set `INOUE_API_KEY` and send the `X-API-Key` header when the API is configured to require authentication.

Requests validate `timeout` between 1 and 120 seconds, batch `workers`
between 1 and 50, and `rate_limit` between greater than 0 and 100 requests
per second. Invalid values receive a validation response instead of starting
a scan. Single-target scans run in a worker thread so the async API event loop
remains responsive.

Both scan endpoints return the complete scan result contract, including IP,
headers, DNS, SSL, WHOIS, subdomains, mail records, ports, directories,
extra intelligence, plugins, notes, errors, and cache status.

For safety, the API rejects credentials in target URLs and blocks private,
loopback, link-local, reserved, and unresolved target addresses by default.
Set `INOUE_ALLOW_PRIVATE_TARGETS=true` only for a deliberately isolated local
lab. Redirects are revalidated at every hop when the public-target policy is
active.

## Browser extension

The repository includes a shared Chrome/Firefox WebExtension in `extension/`.
Start the optional API locally, then load the unpacked `extension/` directory
in the browser. The extension sends the active tab URL to `POST /scan` with
`modules: ["fast"]`, so it performs technology detection without active recon.

The popup supports a configurable API base URL and optional API key. The key
is stored in the browser's extension storage and is sent only as `X-API-Key`.
Localhost is allowed by default; choosing a remote API prompts the browser for
that origin's optional host permission.
Build release archives with:

```bash
python scripts/build_extension.py
```

This writes Chrome and Firefox ZIP archives under `dist/extension/`.

## MCP integration

Model-agnostic: this is a standard MCP server, so any MCP-compatible
client can connect, not just one AI vendor. Install the optional extra
and launch it:

```bash
python -m pip install "inoue[mcp]"
inoue-mcp
```

Defaults to `stdio` (for clients that spawn Inoue as a local subprocess).
For any other MCP-compatible client, serve over HTTP instead:

```bash
inoue-mcp --transport streamable-http
```

Tools: `search_catalog`, `get_catalog_summary`, `scan_read_only`,
`check_waf_tool`, `check_security_headers_tool`, `get_scan_history_tool`,
`check_eol_tool`. All read-only, reusing the local catalog and scanner.
