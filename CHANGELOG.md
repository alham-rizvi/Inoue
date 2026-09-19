# Changelog

## Unreleased

- (nothing yet - see TODO-next-roadmap.md for what's planned next)

## 2.0.0

A major feature release: the fingerprinting engine, recon surface, and every
interface (CLI, API, browser extension, MCP server) were substantially
expanded, and three real crashes/false-positive classes found via live
testing on real targets were fixed at the root.

### Fixed

- **Catalog-wide confidence inflation from duplicate patterns.** 96.5% of
  the signature catalog (10,407 of 10,782 signatures) had the same literal
  word duplicated 3-7 times within one signature's HTML pattern list, an
  artifact of how the catalog was built. The confidence-scoring formula
  treats multiple matching patterns as independent corroborating evidence,
  so a single bare mention of a tool/product name in ordinary page prose
  (a security write-up mentioning "Apache NiFi" or "Pterodactyl" as a CTF
  box, for example) was inflating to "medium" confidence catalog-wide.
  Fixed by deduplicating each signature's pattern lists at compile time;
  genuine multi-signal detections (a real WordPress site's meta generator
  + theme path together) are unaffected.
- **`--full-recon` (and any `--dns` scan) crashed** with
  `KeyError: slice(None, 5, None)` - the CLI's DNS display section assumed
  every `dns_records` value is a list and sliced it, but the DNSSEC entry
  is a dict (`{"ds_present": ..., "dnskey_present": ...}`). Reproduced live,
  fixed, and a regression test confirmed it fails with the exact same error
  when reverted.
- `--dns` (and any single non-tech module) was running the *entire*
  fingerprint engine against the full signature catalog regardless of
  which module was actually requested.
- Dead confidence-threshold branch mislabeled medium-confidence detections
  as high.
- `about`/`update`/`history` CLI subcommands were unreachable - Typer's
  catch-all `targets` argument swallowed every token before Click could
  route to a subcommand.
- `_match_html`'s version-detection fallback used a 360-character window
  around a match, wide enough to bleed a version number from a completely
  unrelated adjacent tag into the wrong technology's result.
- `security_grade`/`http_posture`/`cors_misconfig` were written into
  `result.enriched` before that dict got fully reassigned later in
  `scan()`, silently discarding them on every scan.
- A DNS lookup timeout in the new email-security module was being reported
  as "No SPF record published" - a confidently wrong security claim.
  Genuine record absence (NXDOMAIN/NoAnswer) is now distinguished from a
  failed lookup.
- The `mcp` Python SDK renamed its core server class between v1 (`FastMCP`)
  and v2 (`MCPServer`); a version-unaware install silently reported
  "not installed" even when an incompatible version *was* installed.
  `mcp_server.py` now resolves either API and reports the real error.
- `scripts/build_extension.py` only zipped the top level of `extension/`,
  silently dropping the `assets/` folder (including the logo every release
  archive shipped with a broken image reference).
- The browser extension's own backend dependencies (`fastapi`, `uvicorn`)
  were never in `requirements.txt`, only in `pyproject.toml`'s optional
  `api` extra - the documented "just run uvicorn" setup failed with
  `ModuleNotFoundError` for anyone following it.
- The extension had no toolbar icon at all (`manifest.json` had no `icons`
  field), and the source logo was a wide wordmark unsuitable for a square
  icon regardless.

### Added

**Fingerprinting & version detection**
- ~160 new technology signatures (Next.js, Nuxt, Astro, Remix, Gatsby,
  WooCommerce, Magento, 15+ CMS platforms, Google Tag Manager/Analytics,
  Sentry, Datadog RUM, Auth0, payment processors, chat widgets, and more),
  each using a documented, verifiable detection signal.
- Aggressive version detection: when a technology's own signature pattern
  yields no version, a hunter searches script URLs/headers/nearby HTML for
  one. Every detection now carries `version_source` (`"signature"` for a
  precisely-parsed version vs. `"script-url"`/`"header"`/`"html-near-name"`
  for a hunted one) so a guess is never confused with a trustworthy value.
- Technology end-of-life detection (`core/eol.py`): cross-references
  detected technology + version against a verified EOL table (PHP,
  Node.js, Python - each date checked against the vendor's own
  support-lifecycle page). Feeds the risk score automatically.
- JS bundle intelligence (`core/js_intel.py`): fetches same-origin JS
  bundles and re-runs them through the full fingerprint catalog (closing
  the SPA/client-rendered detection gap), extracts SSR hydration markers,
  candidate API endpoints, and redacted secret-pattern findings (full
  secret values are never logged or stored - only first/last 4 characters).
- Favicon hashing (`core/favicon.py`), extended DNS records (CAA, SOA,
  SRV, DNSSEC presence, reverse DNS), and IP/ASN WHOIS via RDAP.
- Sitemap- and katana-seeded crawl mode (`--crawl`, `--crawl-katana`).

**Web & email security posture**
- WAF/CDN detection (`core/waf.py`) - ~15 vendors, passive only.
- Security header grading + CORS misconfiguration detection
  (`core/security_grade.py`).
- HTTP posture (`core/http_posture.py`): cookie security-flag audit, CSP
  weakness parsing, redirect-chain analysis, HTTP method enumeration via a
  single OPTIONS request.
- Email security (`core/email_security.py`): SPF/DMARC policy analysis,
  DKIM selector probing, MTA-STS/TLS-RPT detection.

**Recon**
- Subdomain takeover fingerprinting (`core/takeover.py`) against ~16
  services' documented "unclaimed resource" error pages.
- API surface discovery (`core/api_discovery.py`): OpenAPI/Swagger spec
  detection, GraphQL introspection status (one minimal query, never
  schema enumeration).
- External tool orchestration (`core/external_tools.py`): subfinder,
  naabu, nmap, nuclei, gau, waybackurls, katana, gowitness - all with
  graceful degradation when a binary isn't installed.
- Scope guardrails (`core/scope.py`, `--scope`): domain wildcard + CIDR
  matching with deny-always-wins semantics. Every module that can fan out
  to hosts beyond the explicit target - subdomain takeover checks across
  discovered subdomains most of all - now respects it, refusing to scan
  an out-of-scope host before making any request at all.

**Triage**
- Risk/triage scoring (`core/risk.py`): combines every signal above into
  a single 0-100 score and band (`investigate-first`/`worth-a-look`/
  `low-signal`/`nothing-notable`), with every contributing factor listed
  for auditability. Explicitly a triage heuristic, never a severity claim.

**Interfaces**
- Append-only scan history with timeline diffing (`--save-history`,
  `inoue history`).
- Browser extension (Chrome/Firefox, Manifest V3) talking to the local
  Python API backend - dark, minimal UI, now with a proper toolbar icon.
- MCP server rewritten: dual v1/v2 SDK support, multi-transport
  (`stdio`/`sse`/`streamable-http` via `--transport`), 7 tools total
  (catalog search, read-only scan, WAF check, security-header check,
  scan history, EOL check).
- FastAPI backend (`api/main.py`) brought to parity with every CLI flag
  added this release across `/scan` and `/scan/batch`.

## 1.1.2 - 2026-09-10

### Added

- bounded watch-scan execution and result diffs for technologies, CVEs, ports,
  and certificate expiry;
- generic, Slack, and Discord webhook payload builders plus HTTPS delivery;
- TLS metadata and known CDN/WAF fingerprint helpers;
- optional FastAPI service endpoints for health, signatures, single scans, and
  batch scans;
- Wappalyzer normalization and duplicate catalog compatibility checks;
- optional EPSS score retention in offline CVE correlation;
- Docker and Compose deployment definitions;
- GitHub Actions PyPI publishing with wheel and sdist validation.

### Fixed

- Python 3.12 plugin imports now defer type annotation evaluation;
- published wheels now include the bundled offline CVE dataset.

## 1.1.0

See the GitHub release notes for the previous release.
