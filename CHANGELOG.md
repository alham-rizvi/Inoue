# Changelog

## Unreleased

- (nothing yet - see ROADMAP.md for what's planned next)

## 2.1.0 - 2026-09-30

A recon-breadth release: ten new keyless recon modules (14 -> 24 modules in the
planner), the follow-up fixes from the v2.0.0 sweep, and a suite that grew from
401 to 574 tests. Still fully read-only, and still no API keys anywhere.

### Added

**Ten new recon modules** (all keyless - no API keys, no accounts)

- **Deep DNS** (`--dns-deep`, module `dnsdeep`): CAA records, SRV service
  discovery, DNSSEC (DS/DNSKEY), NS-to-IP resolution, wildcard-DNS detection,
  and a read-only AXFR zone-transfer attempt. DNS-only.
- **Email authentication** (`--email-auth`, module `emailauth`): BIMI, TLS-RPT,
  a full MTA-STS policy fetch, extended DKIM selector probing with key-size
  estimation, fine-grained DMARC tags (`sp`, `aspf`, `adkim`, `ruf`, `fo`,
  `pct`), and a 0-100 score.
- **ASN intelligence** (`--asn`, module `asn`): ASN, announced prefix,
  organisation, country, registry and allocation date, via Team Cymru DNS.
- **Reputation** (`--reputation`, module `reputation`): Shodan InternetDB
  ports/hostnames/vulnerabilities plus DNS blocklist checks. A resolver that
  refuses a query (for example Spamhaus's refusal range) is reported as
  unverifiable, never as "not listed"; a timeout is likewise "unknown, not
  clean".
- **Cloud bucket enumeration** (`--cloud-buckets`, module `cloud`): derives
  candidate S3/GCS/Azure Blob names from the domain and content-verifies every
  hit, so a provider's catch-all page is not reported as a bucket.
- **Exposure sweep** (`--exposure`, module `exposure`): a fixed list of
  sensitive paths (`.git`, `.env`, backups, dumps, `phpinfo`, `security.txt`,
  `crossdomain.xml`, source maps) with content verification on every 200, so a
  catch-all/soft-404 responder produces no findings.
- **HTTP protocol** (`--http-protocol`, module `protocol`): the negotiated HTTP
  version and TLS protocol (confirmed with one additional request to the
  target), plus HTTP/2, HTTP/3/Alt-Svc, compression and Server-Timing. A single
  HTTP/1.1 result never records HTTP/2 as unsupported - it only reports what
  was observed.
- **Virtual-host discovery** (`--vhost`, module `vhost`): varies the Host
  header against the target IP and keeps only responses that differ from the
  baseline response.
- **Subdomain bruteforce** (`--subdomain-brute`, module `bruteforce`): a
  built-in wordlist plus permutations, with mandatory wildcard-DNS filtering.
- **Subresource Integrity audit** (`--sri`, module `sri`): flags scripts and
  stylesheets loaded without an `integrity` hash, distinguishing same-origin
  from third-party resources.

All ten are selectable by module name or alias (`-m dns-deep`, `-m email-auth`,
`-m cloud-buckets`, `-m http-protocol`, `-m subdomain-brute`, ...).
`-m full-recon` / `-m all` now run all 24 modules, and the new modules are
folded into `-m active` and `-m passive` according to their request profile.

**Libraries**

- New runtime dependencies: `tldextract>=5.1` (BSD-3) for registrable-domain
  parsing, `defusedxml>=0.7` (PSF) so untrusted XML (sitemaps,
  `crossdomain.xml`) cannot trigger XXE or billion-laughs, and `h2>=4.1` (MIT)
  so httpx can negotiate HTTP/2.
- New optional `recon` extra - `wafw00f` (BSD-3), `pydnsbl` (MIT) and `pyasn`
  (MIT) - each imported behind a guard, so a plain install is unaffected.

### Fixed

- **The `update` subcommand was unreachable.** The registered command was
  shadowed by the variadic `targets` argument, so `python inoue.py update`
  scanned the literal string "update" as a target instead of updating the
  clone. It now dispatches, and `update --help` works.
- **`--scope` could not authorise an IP-literal target.** A scope file entry
  such as `127.0.0.1` (or a CIDR) parses as a network, not a domain, and the
  scope gate only ever compared the hostname - so `--scope` refused
  `http://127.0.0.1/` while allowing the very same server reached as
  `http://localhost/`. The gate now accepts a target by name *or* by its
  address, so an entry finally covers the address it names. Deny-always-wins
  and the fail-closed handling of a missing/unreadable scope file are
  unchanged.
- **A completed NXDOMAIN for BIMI/TLS-RPT was reported as unknown.** Both
  lookups returned early for any status other than "ok", so a query that
  completed and found no record was reported as `present=None` ("the lookup did
  not complete") instead of `present=False` (absent). That made the
  "No BIMI record" and "No TLS-RPT record" findings unreachable, and disagreed
  with how DMARC and MTA-STS already reported the identical input. Completed
  and failed lookups are now distinguished for all four record types.
- **BIMI logo and `vmc` URLs kept their trailing `;` separator.** The record is
  semicolon-separated, so a value followed by another tag was returned as
  `https://example.com/logo.svg;`. Tag values are now stripped of the separator
  and any surrounding whitespace.
- **The triage score could not see the new exposure findings.**
  `core/risk.py` read `enriched["exposure"]` as a list of
  `{"url", "status_code"}` rows - a shape the v2 exposure module never produces
  (its payload is a dict of verified `findings` plus unverified `candidates`)
  - so the `exposed_sensitive_file` factor (weight 25) could never fire however
  many `.env` or `.git` disclosures were verified. The scorer now consumes both
  shapes, counts verified file findings, and never lets an unverified candidate
  move the score.
- **A DNSSEC lookup timeout was reported as "not signed".** `_dnssec()`
  derived the flag from whatever came back, so a DS/DNSKEY timeout produced
  `dnssec_signed = False` - a definitive negative - while the same call recorded
  "DNSSEC status is NOT established" in `errors`. It is now tri-state like
  `caa_present`: `True` on material found, `False` only when every lookup
  completed and found nothing, `None` when one failed - and the CLI renders that
  as "unknown (lookup did not complete)" rather than "not signed".
- **Cloud bucket probes over-claimed from ambiguous results.** A connect
  *timeout* was treated as proof a name is not in use, and any status other than
  200/403/404 (a 503, a 429, a WAF block) was reported as "name exists". Only a
  clean 404 and a genuine name-resolution failure now mean "not in use"; a
  timeout, an unexplained connect error, a bare 400 and any undefined status are
  recorded in a new `unverified` list and asserted neither way.
- **`--vhost` was inert against HTTPS-only targets.** The baseline used a
  hardcoded `http://` URL, so an HTTPS-only host failed the baseline and every
  candidate probe with it. The baseline is retried once over the other scheme
  and the scheme that answered is used for every candidate (and reported in the
  result), so the check costs at most one extra request.
- **A comment on the SRI task claimed a network fetch.** The comment above
  `_run_sri` said it "fetches each same-origin script/stylesheet"; `core/sri.py`
  is a pure, offline analyser of the HTML already fetched. The comment now
  matches the code (the nominal `(sri_timeout * 6) + 10` budget is noted as
  symbolic, not a real network allowance).

### Tests

- `tests/test_recon_modules_v2.py` - 83 offline unit tests for the ten new
  modules; the resolver and HTTP client are stubbed, so no test touches the
  network.
- `tests/test_flag_matrix.py` - an end-to-end matrix that runs every documented
  CLI flag once, as a real subprocess, against a local fixture server, plus
  checks that the discovered flag set and value-taking flags match what
  `--help` advertises.
- `tests/test_update_command.py` - 5 regression tests for the `update`
  dispatch and its neighbouring subcommands.
- Suite grew from 401 to 574 tests, 0 failures.

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
