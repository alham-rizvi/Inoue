# Inoue commands and usage

This file documents the main commands and flags supported by Inoue.

## Watch and diff scans

The library exposes `watch_scan_loop` and `diff_scan_results` for applications
that run repeated foreground scans and compare technology, CVE, port, and
certificate changes. The loop is intentionally bounded and does not create a
daemon or service-manager process.

## Webhook delivery

Use the payload builders in `core.webhooks` for generic, Slack, or Discord
notifications. `send_webhook` posts only to the caller-provided URL with TLS
verification enabled by default. Keep webhook URLs in environment variables or
local configuration; never commit credentials.

## API server

Install the optional API dependencies and start the server with:

```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

See [API.md](API.md) for endpoint payloads, authentication, and batch limits.

## Browser extension

Build Chrome and Firefox release archives for the local Python API:

```bash
python scripts/build_extension.py
```

Load `extension/` unpacked during development. The popup scans the active
HTTP(S) tab through `POST /scan` using the `fast` module preset. Configure a
different local API URL or API key from the popup settings.

## MCP server

Model-agnostic by design: this is a standard Model Context Protocol
server, so any MCP-compatible client can connect - not anything specific
to one AI vendor or model.

Install the optional dependency and start the server:

```bash
python -m pip install "inoue[mcp]"
inoue-mcp
```

By default it serves over `stdio` (for clients that spawn Inoue as a
local subprocess, like Claude Desktop or Claude Code). For any other
MCP-compatible client - a web-based client, a remote agent, anything that
connects over HTTP instead of spawning a subprocess - serve over HTTP
instead:

```bash
inoue-mcp --transport streamable-http
# or: inoue-mcp --transport sse
# or via env var: INOUE_MCP_TRANSPORT=streamable-http inoue-mcp
```

Works with both major versions of the underlying `mcp` SDK (`FastMCP` in
v1, renamed to `MCPServer` in v2) - it detects whichever is installed and
gives a clear error naming the actual problem if neither resolves,
instead of a misleading "not installed" message when an incompatible
version is present.

Available tools:

- `search_catalog` / `get_catalog_summary` - local signature catalog only, no network requests
- `scan_read_only` - full technology fingerprint scan (same engine as the CLI)
- `check_waf_tool` - fast, passive-only WAF/CDN check (one request, no full scan)
- `check_security_headers_tool` - security header grade + CORS misconfiguration check (one request)
- `get_scan_history_tool` - read previously saved scan history for a target; never triggers a new scan

The server does not expose exploit, write, or credential automation
operations - every tool is read-only.

## Terminal presentation

Set editable colors and layout in `.inoue.toml` or
`~/.config/inoue/config.toml`:

```toml
[terminal]
text_style = "bright_white"
layout = "compact"

[terminal.colors]
"Web Server" = "bright_cyan"
"CMS" = "yellow"
```

Use `compact`, `standard`, or `wide` layouts. CLI flags continue to override
operational configuration; terminal presentation settings only affect output.

## Run the scanner

```bash
python inoue.py <target>
```

The CLI now shows live scan progress while each target is scanned and reports discoveries as they are identified.

Examples:

```bash
python inoue.py alhamrizvi.in
python inoue.py https://alhamrizvi.in
python inoue.py 10.10.10.10
```

## Service-only scan

```bash
python inoue.py --service <target>
```

Detects only services and technologies exposed by the target.

## Header-based scan

```bash
python inoue.py --headers <target>
```

Run only header-based fingerprint detection.

## DNS enumeration

```bash
python inoue.py --dns <target>
```

Enable DNS lookup for the target.

## SSL inspection

```bash
python inoue.py --ssl <target>
```

Enable SSL/TLS inspection for the target.

## Whois lookup

```bash
python inoue.py --whois <target>
```

Perform a whois lookup for the target domain.

## Subdomain enumeration

```bash
python inoue.py --subdomains <target>
```

Collect discovered subdomains for the target.

## Mail record lookup

```bash
python inoue.py --mail <target>
```

Query MX records for the target.

## Common port scan

```bash
python inoue.py --ports <target>
```

Scan common ports on the target host.

## Extra reconnaissance intelligence

```bash
python inoue.py --extra <target>
```

Enable additional public intelligence and directory enumeration.

## Fast preset

```bash
python inoue.py --fast <target>
```

Run a quick scan using only headers and technology detection.

## Full recon preset

```bash
python inoue.py --full-recon <target>
```

Run a full recon-style scan with all enabled modules.

## All modules

```bash
python inoue.py --all <target>
```

Enable every recon and detection module.

## Verbose output

```bash
python inoue.py -v <target>
```

Shows SSL information, DNS records, security headers, and response headers.

## Show detection evidence

```bash
python inoue.py -e <target>
```

Shows the evidence string that triggered each fingerprint match.

## Full recon-style scan

```bash
python inoue.py -v -e <target>
```

## Disable DNS lookup

```bash
python inoue.py --no-dns <target>
```

## Disable SSL inspection

```bash
python inoue.py --no-ssl <target>
```

## Set request timeout

```bash
python inoue.py -t 5 <target>
```

## Scan multiple targets

```bash
python inoue.py site1.com site2.com site3.com

Read targets from a file or stdin for shell pipelines:

```bash
python inoue.py --list targets.txt
cat targets.txt | python inoue.py --json
```
```

Limit requests per host during async batch scans:

```bash
python inoue.py --rate-limit 1 alhamrizvi.in
```
```

## JSON output

```bash
python inoue.py --json alhamrizvi.in
```

Save JSON to a file:

```bash
python inoue.py --json -o results.json alhamrizvi.in

Save a self-contained HTML report:

```bash
python inoue.py -o report.html alhamrizvi.in
```

## Local cache

```bash
python inoue.py --cache --cache-ttl 3600 alhamrizvi.in
```

The default cache is `~/.cache/inoue/cache.db`; use `--cache-path` to override it.

Default operational values may be stored in `.inoue.toml` or
`~/.config/inoue/config.toml`. Precedence is CLI flag, project config, user
config, then built-in default. Example:

```toml
rate_limit = 2
cache = true
cache_ttl = 3600
cve = true
cve_min_severity = "high"
plugin_dir = "./modules"
```

## CVE awareness

```bash
python inoue.py --cve alhamrizvi.in
```

This uses the bundled offline dataset and reports informational matches only.

Filter CVE output by severity:

```bash
python inoue.py --cve --cve-min-severity high alhamrizvi.in
```

Use `--fail-on-cve` to return exit code `2` when a matching CVE is found.
Exit code `1` indicates one or more scan errors; `0` means the scan completed
without those conditions. Argument errors remain exit code `2`.

Refresh the local dataset explicitly from an NVD JSON feed:

```bash
python inoue.py update-cve
```

Use `--source-url` for a reviewed feed mirror and `-o` to write a separate dataset file.

## WAF / CDN detection

Automatic on every scan, no flag needed - Inoue checks the headers/cookies
it already fetched against a catalog of ~15 major WAF/CDN vendors
(Cloudflare, Akamai, CloudFront, AWS WAF, Incapsula, Sucuri, Fastly, Azure
Front Door, F5, and others). Purely passive: no extra requests, no probing.

Shown as its own section above the technology table, and available as
`result.waf` / the `waf` field in JSON output.

## Security header grade and CORS check

Also automatic and free - computed from the same headers as every other
check. Reports which of the six common protective headers
(HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy) are present, with a 0-100 score, and flags the two
CORS misconfiguration patterns that are almost always a real problem:
a wildcard origin combined with credentials allowed, or a specific origin
allowed alongside credentials (worth checking whether it's actually
reflected rather than allowlisted). A bare wildcard origin with no
credentials header is the normal way to serve a public API and is never
flagged.

Available as `security_grade` / `cors_misconfig` in JSON output.

## Favicon hashing

Computed automatically whenever technology detection runs (part of the
`tech` module / default scan). Fetches the page's favicon, hashes it
(md5 always; mmh3/Shodan-style hashing when the optional `mmh3` package
is installed), and checks it against `fingerprints/favicon_hashes.py`.

The catalog ships empty by design - favicon bytes vary across
software/theme versions, and a wrong hash produces a false positive that
is worse than no signal. Populate it yourself with verified hashes:

```bash
python scripts/collect_favicon_hash.py https://known-instance.example "TechName" "Category"
```

## Extended DNS and WHOIS records

The `--dns` module now also resolves CAA, SOA, and SRV records, checks
for DNSSEC (DS/DNSKEY presence), and does a reverse DNS (PTR) lookup on
every resolved IP. The `--whois` module now also does an IP/ASN WHOIS
lookup via RDAP - who owns the network block the target's IP sits in, not
just who owns the domain name.

## Crawl mode

```bash
python inoue.py --crawl 3 <target>
```

Fetches up to N additional same-origin pages and fingerprints each,
merging in anything new (medium/high confidence only, to avoid flooding
results with weak path-only matches from secondary pages). Candidates
come from `sitemap.xml` (including one level of sitemap-index following)
and on-page links by default.

```bash
python inoue.py --crawl 5 --crawl-katana <target>
```

Adds katana (if installed) as an extra crawl-candidate source for
JS-aware link discovery beyond plain `<a href>` scanning.

## JS bundle intelligence

```bash
python inoue.py --js-intel <target>
python inoue.py --js-intel --js-intel-bundles 5 <target>
```

Fetches the page's own JS bundles (bounded, default 3, size-capped) and:

- Feeds the bundle text back through the full ~21,000-signature
  fingerprint catalog, so client-rendered stacks (React, Vue, Next.js,
  Nuxt...) that never appear in the static HTML alone can still be
  detected. These detections are tagged `[JS bundle]` in evidence output.
- Detects SSR/hydration markers (`window.__NEXT_DATA__`, `__NUXT__`,
  `__APOLLO_STATE__`, etc.) directly from the initial HTML.
- Extracts candidate API endpoint paths referenced in the bundles - a
  recon signal for later fuzzing with a dedicated tool, never probed by
  Inoue itself.
- Pattern-matches likely leaked credentials (AWS keys, Google API keys,
  Slack tokens, Stripe keys, generic bearer tokens). Every match is
  **redacted to first/last 4 characters** before it's ever returned -
  the full secret value is never logged, stored, or displayed.

Available as `js_intel` in JSON output.

## Scope guardrails

```bash
python inoue.py --scope program-scope.txt <target>
```

Every module that can fan out to hosts beyond the one explicitly typed on
the command line - subdomain takeover checks across discovered
subdomains being the highest-risk case - respects a declared scope
before firing a single request at a host you never authorized scanning.

Scope file format (plain text, one entry per line, safe to paste a
program's published scope list in with minimal editing):

```
# comment
example.com            # exact host
*.example.com          # wildcard subdomain
10.0.0.0/8              # CIDR range
!internal.example.com  # explicit deny - always wins over a broader allow
!10.1.0.0/16
```

No `--scope` flag means unrestricted (the default, unchanged behavior).
When a scope file is given and the target isn't in it, Inoue refuses to
scan **before making any request at all** - not after, not partially.

## Subdomain takeover detection

```bash
python inoue.py --check-takeover --subdomains <target>
```

Checks the target and any discovered subdomains against the well-known
"this service exists but the resource doesn't" error pages (S3, GitHub
Pages, Heroku, Shopify, Netlify, Webflow, Zendesk and ~10 more). A
matching CNAME raises the reported confidence from medium to high.

Strictly detection-only: Inoue issues a plain GET and matches the
response body. It never attempts to register, claim, or create anything
on the third-party service. Every finding is labelled a *candidate* and
carries a "verify manually" caveat - several of these fingerprints can
also appear on healthy-but-misconfigured hosts.

## API surface discovery

```bash
python inoue.py --api-discovery <target>
```

Probes a fixed list of conventional, framework-default documentation
paths (`/swagger.json`, `/openapi.json`, `/api-docs`,
`/.well-known/security.txt`, `/.well-known/openid-configuration`) - not a
brute-force wordlist - and reports any readable OpenAPI/Swagger spec
along with its title and documented path count.

For GraphQL, it sends exactly one minimal introspection query to
determine whether **introspection is enabled** - a legitimate finding on
its own, since an open introspection endpoint hands over the full schema.
It stops there; no schema enumeration, no follow-up queries.

## Technology end-of-life detection

Automatic on every scan whenever a versioned technology is detected -
no flag needed. Cross-references detected technology + version against
a static table of verified EOL dates (currently PHP, Node.js, and Python
- each date checked against the vendor's own support-lifecycle page).
Running EOL software means no further security patches, a frequently
reported finding in its own right.

Absence from the table means "not checked", never "not EOL" - this is a
static reference table, not a live feed, and it will go stale. Available
as `eol_technologies` in JSON output, and feeds the triage risk score.

## Triage scoring

Computed automatically on every scan, no flag needed. Combines every
other signal Inoue collected - takeover candidates, secrets found in JS
bundles, CVE severity counts, exposed sensitive files, GraphQL
introspection, readable API specs, CORS misconfigurations, missing WAF,
weak security headers, open port count - into a single 0-100 score and
one of four bands:

- `investigate-first` (60+)
- `worth-a-look` (30-59)
- `low-signal` (1-29)
- `nothing-notable` (0)

This exists to **order a list of targets**, which is the real workflow
when you have 200 subdomains and limited time. It is explicitly a triage
heuristic, not a severity rating or a vulnerability claim - every
contributing factor is reported alongside the score so the ranking is
auditable and you can disagree with it.

Available as `risk` in JSON output; `core.risk.rank_results()` ranks many
scan results highest-signal-first.

## Scan history

```bash
python inoue.py --save-history <target>
python inoue.py history <target>
python inoue.py history <target> --json
```

`--save-history` appends the scan result to a local, append-only SQLite
database (`~/.cache/inoue/history.db` by default, override with
`--history-path`). Nothing is ever written automatically - only when you
explicitly ask. `inoue.py history <target>` then shows a timeline of what
changed (technologies added/removed/version-bumped, CVEs, open ports,
certificate expiry) across every saved snapshot for that target. This is
a separate store from `--cache`, which only ever keeps the most recent
result per target.

## External security tool integrations

Inoue can shell out to real, purpose-built tools when they're installed,
rather than reimplementing them badly. Every integration degrades
gracefully (reports "not found on PATH" with an install hint) when the
tool isn't present - none of these are required dependencies.

```bash
python inoue.py --active-subdomains <target>       # subfinder
python inoue.py --active-ports <target>             # naabu (discovery) + nmap -sV (service ID)
python inoue.py --nuclei <target>                   # nuclei vulnerability templates
python inoue.py --nuclei --nuclei-severity high,critical <target>
python inoue.py --harvest-urls <target>             # gau + waybackurls + katana, merged and deduped
python inoue.py --screenshot --screenshot-dir ./shots <target>   # gowitness (needs Chrome/Chromium too)
```

Install whichever you want:

```bash
sudo apt-get install -y nmap
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/sensepost/gowitness@latest   # also needs Chrome/Chromium
```

Results land in `enriched.external_tools` in JSON output, with each
tool's `available`/`results`/`error`/`note` reported separately so a
missing binary, a tool that ran and found nothing, and a tool that
errored are never confused with each other.

All of the above are also available on `--all`/`--full-recon` runs via
the equivalent `scan()`/API parameters, and through the FastAPI
`/scan` and `/scan/batch` endpoints (`active_subdomains`, `active_ports`,
`nuclei_scan`, `nuclei_severity`, `harvest_urls`, `screenshot`,
`screenshot_dir`, `crawl_pages`, `crawl_katana`, `js_intel`,
`js_intel_bundles`, `save_history`).



```bash
python inoue.py --nuclei-out nuclei-targets.json alhamrizvi.in
```

The export is a JSON mapping of normalized technology tags to target URLs.

## Plugins

Place a Python plugin defining `run(result)` in `modules/` or `~/.config/inoue/modules/`, or pass `--plugin-dir PATH`.

## Catalog maintenance

Normalize a local Wappalyzer catalog in dry-run mode:

```bash
python scripts/import_wappalyzer.py wappalyzer.json
```

Persist reviewed normalized entries explicitly with `--write --output FILE`.
Audit signature provenance with:

```bash
python scripts/audit_signatures.py --stale-days 180
```
```

## Worker count

```bash
python inoue.py -w 10 alhamrizvi.in
```

## Hide banner

```bash
python inoue.py --no-banner <target>
```

## Optional enrichment API key

```bash
python inoue.py --api-key <key> <target>
```

## Update the local clone from the repository

Fetch and apply the latest fingerprints, scanner improvements, and catalog updates:

```bash
python inoue.py update
```

This command:
1. Runs `git fetch --all --prune` to pull all remote changes
2. Runs `git pull --ff-only` to merge fast-forward updates only
3. Displays a summary of recent commits and modified files
4. Updates cached signatures for immediate use

**What gets updated:**
- New fingerprints in `fingerprints/signatures.py` and `fingerprints/extended_catalog.py` (~21,000 signatures combined)
- Scanner improvements in `core/scanner.py`
- CLI and command enhancements in `inoue.py`
- Documentation updates in `GUIDE.md`, `CONTRIBUTING.md`, `COMMANDS.md`

After running `update`, all future scans will use the new signatures and detection logic without restarting the tool.

## Fast HTB/CTF style scan

```bash
python inoue.py --no-dns -t 5 10.10.11.55
```

## Common combinations

```bash
# Full recon with evidence and JSON export
python inoue.py -v -e --json -o results.json https://alhamrizvi.in

# Fast scan for a lab target
python inoue.py --no-dns -t 5 10.10.11.55

# Scan multiple hosts in parallel
python inoue.py -w 10 site1.com site2.com site3.com

# Bug bounty recon pass: crawl + JS intel + active subdomains + nuclei,
# save a history snapshot for later diffing
python inoue.py --crawl 5 --js-intel --active-subdomains --nuclei \
  --save-history --json -o recon.json https://target.example
```
