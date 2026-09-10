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

## MCP server

Install the optional dependency and start the stdio MCP server:

```bash
python -m pip install "inoue[mcp]"
inoue-mcp
```

Available tools are `search_catalog`, `get_catalog_summary`, and
`scan_read_only`. The server does not expose exploit, write, or credential
automation operations.

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
python inoue.py example.com
python inoue.py https://target.example
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

Limit requests per host during async batch scans:

```bash
python inoue.py --rate-limit 1 target.com
```
```

## JSON output

```bash
python inoue.py --json <target>
```

Save JSON to a file:

```bash
python inoue.py --json -o results.json <target>

Save a self-contained HTML report:

```bash
python inoue.py -o report.html <target>
```

## Local cache

```bash
python inoue.py --cache --cache-ttl 3600 <target>
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
python inoue.py --cve <target>
```

This uses the bundled offline dataset and reports informational matches only.

Filter CVE output by severity:

```bash
python inoue.py --cve --cve-min-severity high <target>
```

Use `--fail-on-cve` to return exit code `2` when a matching CVE is found.
Exit code `1` indicates one or more scan errors; `0` means the scan completed
without those conditions. Argument errors remain exit code `2`.

Refresh the local dataset explicitly from an NVD JSON feed:

```bash
python inoue.py update-cve
```

Use `--source-url` for a reviewed feed mirror and `-o` to write a separate dataset file.

## Nuclei export

```bash
python inoue.py --nuclei-out nuclei-targets.json <target>
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
python inoue.py -w 10 <target>
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
- New fingerprints in `fingerprints/signatures.py` (700+ core signatures)
- Extended catalog entries in `fingerprints/extended_catalog.py`
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
python inoue.py -v -e --json -o results.json https://target.example

# Fast scan for a lab target
python inoue.py --no-dns -t 5 10.10.11.55

# Scan multiple hosts in parallel
python inoue.py -w 10 site1.com site2.com site3.com
```
