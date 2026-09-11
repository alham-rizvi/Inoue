# Project overview

Inoue is a reconnaissance-oriented technology fingerprinting project built around a single scanner core and a small set of user-facing surfaces: the CLI, the optional API, and the browser extension. The project focuses on read-only observation of public web surfaces, using HTTP metadata, HTML patterns, DNS and certificate data, and curated signature entries to infer the technologies exposed by a website or service.

## Core purpose

The project answers questions such as:

- What frameworks, servers, CMS platforms, libraries, or admin panels are visible?
- Which versions are likely running?
- Are there relevant CVE exposures based on a matching version?
- What extra recon data is available without crossing into active exploitation?

The scanner is intentionally conservative: it uses observable evidence, keeps the output transparent, and stays within an operational, read-only scope.

## Repository map

- `inoue.py` — CLI entry point and result rendering
- `api/main.py` — optional FastAPI server for scan and signature endpoints
- `core/scanner.py` — detection engine, recon orchestration, network helpers, and result serialization
- `core/config.py` — configuration precedence and local defaults
- `core/cache.py` — optional SQLite-backed scan caching
- `core/cve.py` — local CVE matching logic
- `core/plugins.py` — plugin loading and error isolation
- `core/terminal.py` — Rich terminal formatting settings
- `fingerprints/signatures.py` — primary catalog for service and technology detection
- `fingerprints/extended_catalog.py` — additional catalog entries and complementary signatures
- `fingerprints/web_server_catalog.py` — server-family, reverse-proxy, and forwarding-proxy entries
- `scripts/` — validation, import, and release tooling
- `tests/` — scanner, API, and extension regression coverage

## Execution model

1. The CLI resolves flags and target list.
2. The scanner normalizes the target and issues HTTP requests.
3. It collects headers, cookies, HTML, script references, and URL patterns.
4. Matching runs against the compiled signature catalog.
5. Recon modules can enrich the result with DNS, SSL, WHOIS, subdomains, mail records, port hints, and public intelligence.
6. The final object is serialized for terminal output, JSON export, HTML output, or API responses.

## Security posture

This project is a read-only reconnaissance tool. The default API behavior rejects private and non-public targets, prevents credential-bearing URLs, and constrains batch size and rate limits. It is not designed to act as an SSRF proxy or to enable target-side writes. The CLI still permits local testing for authorized use, but the default API path is safe-by-default.

## Output contract

The scanner result is expected to stay stable enough for automation. The same result object can be rendered for human output, exported to JSON, turned into Markdown/HTML reports, or returned through the API. Keeping that contract stable matters more than adding convenience-only fields.

## Extension and API relationship

The browser extension is intentionally a thin client. It reads the active tab URL and calls the scanner API with a fast preset rather than re-implementing detection logic in the browser. This keeps technology detection consistent between CLI, API, and browser integrations.

## Contribution guidance

When changing detection behavior, prefer targeted updates to registry entries and small regression tests over broad rewrites. The safest work in this project is usually a specific signature adjustment plus the matching fixture or unit test that proves the behavior.
