<h1 align="center">
  <img width="150" height="150" alt="Green Black Professional Minimal Fashion Brand Logo" src="https://github.com/user-attachments/assets/b2277aa7-5c74-4bb0-86bd-b7c98b5dbbbe" alt="Inoue" width="64" valign="middle" /> Inoue

</h1>

<p align="center">
  <a href="https://github.com/alham-rizvi/Inoue"><img src="https://img.shields.io/github/stars/alham-rizvi/Inoue?style=flat&label=%E2%98%85&color=08C" alt="GitHub stars" /></a>
  <a href="https://pypi.org/project/inoue/"><img src="https://img.shields.io/pypi/v/inoue?style=flat&color=08C" alt="PyPI version" /></a>
  <img src="https://img.shields.io/badge/license-MIT-08C?style=flat" alt="License: MIT" />
  <img src="https://img.shields.io/badge/python-3.12-4493F8?style=flat-square" alt="Python 3.12" />
</p>

<p align="center">
  <strong>A fast, open-source recon-oriented tech stack fingerprinting CLI.</strong><br/>
  Identify the technologies exposed by a target website or service, straight from the terminal.
</p>

<h3 align="center"><a href="https://github.com/alham-rizvi/Inoue"><ins>View on GitHub</ins></a></h3>

<p align="center">
 <img width="640" height="320" alt="e (2)" src="https://github.com/user-attachments/assets/84fee62f-d7b1-4c8e-bd54-6fc46a57fe17"
 alt="Inoue announcement banner" width="640" />
</p>

Inoue is designed to identify the technologies exposed by a target website or service, with a broad signature catalog that covers servers, runtimes, CMS platforms, ecommerce stacks, frameworks, JavaScript libraries, analytics tools, payment providers, admin panels, cloud/self-hosted management surfaces, VPN portals, and IoT/admin devices.

It is useful for recon, CTF/HTB, bug bounty, internal network review, and general surface analysis.

Maintained by **Alham Rizvi**.

## Version 1.1.2

The current release adds a safer release-ready recon workflow while keeping scanning read-only:

- repeated watch scans and structured technology, CVE, port, and certificate diffs
- generic, Slack, and Discord webhook payloads with verified HTTPS delivery
- best-effort TLS metadata and known CDN/WAF fingerprint matching
- optional FastAPI endpoints for health, signature, single-target, and batch scans
- async/API scans preserve selected recon modules, use bounded request validation, and return the full scan result contract
- shared Chrome and Firefox extension for detecting the active tab's web stack through the local Python API
- Wappalyzer catalog normalization with duplicate compatibility checks
- offline CVE correlation with optional EPSS scores and explicit refresh only
- Python 3.12 CI coverage and PyPI package publishing through GitHub Actions

The bundled offline CVE dataset is included in published wheels.

## Features

<table>
<tr>
<td width="50%" valign="middle">

### Broad Signature Catalog

600+ services covering web servers, languages, frameworks, CMS, ecommerce, JS libraries, analytics, payments, CDNs, WAFs, cloud portals, ICS/SCADA surfaces, admin panels, and network appliances.

</td>
<td width="50%">
  <img src="https://private-user-images.githubusercontent.com/226852768/614816041-e2101e22-1391-4056-a98a-d65f1a6f8a5f.png" alt="Inoue scan output" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### Multi-Signal Detection

Detects technologies from HTTP headers, cookies, HTML body content, script tags, meta tags, and common login/admin URL paths — each match enriched with confidence, version hint, and evidence.

[Docs →](https://github.com/alham-rizvi/Inoue/blob/main/GUIDE.md)

</td>
<td width="50%">
  <img src="https://private-user-images.githubusercontent.com/226852768/614816041-e2101e22-1391-4056-a98a-d65f1a6f8a5f.png" alt="Inoue evidence detection" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### SSL, DNS & Security Auditing

SSL/TLS inspection with certificate metadata and handshake details, DNS intelligence across A, AAAA, MX, NS, TXT, and CNAME records, and security header auditing for HSTS, CSP, X-Frame-Options, and related protections.

</td>
<td width="50%">
  <img src="https://private-user-images.githubusercontent.com/226852768/614816041-e2101e22-1391-4056-a98a-d65f1a6f8a5f.png" alt="Inoue SSL and DNS output" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### CVE Correlation

Correlate detected versions against a local, offline CVE dataset with optional EPSS scores. Refreshed explicitly, never silently, so scans stay reproducible.

[Docs →](https://github.com/alham-rizvi/Inoue/blob/main/COMMANDS.md)

</td>
<td width="50%">
  <img src="https://private-user-images.githubusercontent.com/226842068/614790703-3ebec879-7fdb-4ee4-9def-277e95b1c406.png" alt="Inoue CVE correlation" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### Watch Mode & Webhooks

Run repeated watch scans with structured technology, CVE, port, and certificate diffs, delivered over generic, Slack, or Discord webhook payloads with verified HTTPS delivery.

</td>
<td width="50%">
  <img src="https://private-user-images.githubusercontent.com/226852768/614816041-e2101e22-1391-4056-a98a-d65f1a6f8a5f.png" alt="Inoue watch mode" width="100%" />
</td>
</tr>
<tr>
<td width="50%" valign="middle">

### API, MCP & Browser Extension

Optional FastAPI endpoints for health, signature, single-target, and batch scans; an MCP server over stdio for catalog search and read-only scans; and a shared Chrome/Firefox extension for detecting the active tab's stack.

[Docs →](https://github.com/alham-rizvi/Inoue/blob/main/docs/WIKI.md)

</td>
<td width="50%">
  <img src="https://private-user-images.githubusercontent.com/226842068/614790703-3ebec879-7fdb-4ee4-9def-277e95b1c406.png" alt="Inoue API and MCP" width="100%" />
</td>
</tr>
</table>

**Also in the box:**

- **Parallel scanning** — multiple targets at once with configurable worker count
- **Structured JSON output** — for automation and reporting, optionally saved to file
- **Rate limiting & caching** — `--rate-limit` and an opt-in local SQLite cache with configurable TTL
- **Nuclei export** — write technology-tagged target groups as JSON for downstream nuclei workflows
- **Configurable terminal presentation** — layout and colors via `.inoue.toml` or `~/.config/inoue/config.toml`
- **Extensible signature engine** — add new detections by editing a single Python dict
- **And more** — see [COMMANDS.md](COMMANDS.md) for the full reference



## Install

```bash
python -m pip install inoue==1.1.2
inoue --help
```

Install the optional API dependencies with:

```bash
python -m pip install "inoue[api]==1.1.2"
```

Install optional MCP support with:

```bash
python -m pip install "inoue[mcp]"
inoue-mcp
```

_Or from source:_

```bash
git clone https://github.com/alham-rizvi/Inoue.git
cd Inoue
pip install -r requirements.txt
```

The browser extension is built from the same repository for both Chrome and Firefox. Start the API, then package it with:

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
python scripts/build_extension.py
```

Load the generated ZIP or the `extension/` directory as an unpacked extension.



## Usage

```bash
# Basic scan
python inoue.py alhamrizvi.in

# Verbose scan with SSL, DNS, headers, and security inspection
python inoue.py -v alhamrizvi.in

# Show the evidence behind each detection
python inoue.py -e https://alhamrizvi.in

# Full recon-style scan
python inoue.py -v -e https://alhamrizvi.in

# Scan multiple targets concurrently
python inoue.py site1.com site2.com site3.com

# Read targets from a file or stdin pipeline
python inoue.py --list targets.txt
cat targets.txt | python inoue.py --json

# Rate-limit and cache repeat scans
python inoue.py --rate-limit 1 --cache alhamrizvi.in

# Correlate detected versions with the local CVE dataset
python inoue.py --cve alhamrizvi.in
python inoue.py --cve --cve-min-severity high alhamrizvi.in
python inoue.py --cve --fail-on-cve alhamrizvi.in

# Refresh the local CVE dataset explicitly
python inoue.py update-cve

# Export technology-tagged URLs for downstream nuclei workflows
python inoue.py --nuclei-out nuclei-targets.json alhamrizvi.in

# JSON output
python inoue.py --json alhamrizvi.in
python inoue.py --json -o results.json alhamrizvi.in
python inoue.py -o report.html alhamrizvi.in

# Fast HTB/CTF style scan without DNS
python inoue.py --no-dns -t 5 10.10.11.55

# Skip SSL checks for HTTP-only or self-signed targets
python inoue.py --no-ssl https://alhamrizvi.in

# Pull the latest catalog and scanner updates from the repository
python inoue.py update
```

For a full command reference, see [COMMANDS.md](COMMANDS.md).

For deeper implementation notes and backend context, see the project guides in [guides/README.md](guides/README.md). For installation, MCP, terminal themes, Docker, verification, and release publishing, see [the repository wiki guide](docs/WIKI.md).

Operational defaults can be stored in project `.inoue.toml` or user `~/.config/inoue/config.toml`; CLI flags always take precedence.

Terminal presentation can be customized in the same TOML file:

```toml
[terminal]
text_style = "bright_white"
layout = "wide" # compact, standard, or wide

[terminal.colors]
"Web Server" = "bright_cyan"
"Application Server" = "green"
"Other" = "grey70"
```



## Options

| Flag | Description |
|---|-------------|
| `-v, --verbose` | Show SSL info, DNS records, security headers, and response headers |
| `-e, --evidence` | Show the evidence that triggered each detection |
| `--no-dns` | Skip DNS enumeration |
| `--no-ssl` | Skip SSL/TLS inspection |
| `--service` | Run service/technology fingerprint detection only |
| `--headers` | Enable header-based detection |
| `--dns` | Enable DNS enumeration |
| `--ssl` | Enable SSL inspection |
| `--whois` | Enable whois lookup |
| `--subdomains` | Enable subdomain enumeration |
| `--mail` | Enable mail record lookup |
| `--ports` | Enable common port scanning |
| `--extra` | Enable extra reconnaissance intelligence |
| `--fast` | Fast scan preset (headers + tech) |
| `--full-recon` | Full recon preset |
| `--all` | Enable all recon modules |
| `-t, --timeout` | HTTP timeout in seconds (default: 10) |
| `-w, --workers` | Concurrent scan threads (default: 5) |
| `-l, --list` | Read one target per line from a file |
| `--rate-limit` | Maximum requests per second per host |
| `--cache` | Enable the opt-in local SQLite cache |
| `--cache-path` | Override the SQLite cache path |
| `--cache-ttl` | Cache lifetime in seconds |
| `--cve` | Match detected versions against the local CVE dataset |
| `--nuclei-out` | Write technology-tagged target groups as JSON |
| `--plugin-dir` | Load result plugins from an additional directory |
| `--json` | Output results as JSON |
| `-o, --output` | Save JSON to a file |
| `--no-banner` | Suppress the ASCII banner |
| `--api-key` | Optional API key for enrichment services |



## What it can identify

Inoue is built around a large signature catalog and can surface technologies across categories such as:

- **Web servers:** Apache, Nginx, IIS, LiteSpeed, Caddy, Tomcat, OpenResty
- **Languages and runtimes:** PHP, ASP.NET, Node.js, Python, Ruby on Rails, Java, Go
- **Frameworks:** Laravel, Django, Flask, Express.js, Spring, Symfony, FastAPI, Next.js, React, Vue, Angular
- **CMS and ecommerce:** WordPress, Drupal, Joomla, Magento, Shopify, PrestaShop, OpenCart, Ghost
- **Analytics and marketing:** Google Analytics, Tag Manager, Hotjar, Matomo, Plausible, Segment, Mixpanel
- **Payments:** Stripe, PayPal, Braintree, Authorize.Net, Square, Adyen, Paddle
- **CDNs and security:** Cloudflare, CloudFront, Fastly, Akamai, Varnish, WAF products
- **Admin and management panels:** phpMyAdmin, Adminer, pgAdmin, Webmin, Portainer, Jenkins, GitLab, Jira, Confluence, and more
- **Cloud and self-hosted infrastructure:** OpenStack, OpenShift, Proxmox, oVirt, CloudStack, Rancher, Harbor, Nextcloud, OwnCloud
- **VPN and remote access:** OpenVPN, WireGuard, Tailscale, pfSense, OPNsense, FortiGate, UniFi, MikroTik
- **IoT and appliance surfaces:** Home Assistant, OpenHAB, Synology DSM, QNAP QTS, TrueNAS, routers, cameras, and printer web consoles

## How detection works

The scanner evaluates several signal sources in order:

- HTTP response headers
- Cookies
- HTML body content
- Script tags and referenced assets
- Meta tags
- URL paths and common login/admin routes

Each detection is enriched with a confidence level, version hint when available, and evidence from the matched signal.

## Adding signatures

Edit [fingerprints/signatures.py](fingerprints/signatures.py). Each entry follows this schema:

```python
"TechName": {
    "category": "Framework",
    "headers": {"Header-Name": r"regex(with optional (version) group)"},
    "cookies": [r"cookie_name_pattern"],
    "html": [r"pattern in response body"],
    "scripts": [r"pattern in <script src=...>"],
    "meta": {"generator": r"pattern"},
    "paths": [r"/common/admin/path"],
},
```

Normalize a reviewed Wappalyzer catalog without changing scans:

```bash
python scripts/import_wappalyzer.py wappalyzer.json
python scripts/import_wappalyzer.py wappalyzer.json --write --output imported.json
```

## Example JSON output

```json
[
  {
    "url": "https://target.com",
    "ip": "1.2.3.4",
    "status_code": 200,
    "response_time_ms": 142.3,
    "server": "nginx",
    "technologies": [
      {"name": "Nginx", "category": "Web Server", "version": "1.24.0", "evidence": "Server: nginx/1.24.0"},
      {"name": "WordPress", "category": "CMS", "version": "6.5", "evidence": "Meta generator: WordPress 6.5"}
    ],
    "ssl": {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
    "dns": {"A": ["1.2.3.4"], "MX": ["mail.target.com"]}
  }
]
```



## Roadmap

Planned improvements include:

- more signature coverage for modern web stacks
- broader version heuristics and enrichment sources
- deeper TLS and header analysis
- better structured reports for recon workflows



## Community & Support

- **Issues & Feature Requests:** [Open an issue](https://github.com/alham-rizvi/Inoue/issues)
- **Discussions:** Join the conversation on [GitHub Discussions](https://github.com/alham-rizvi/Inoue/discussions)
- **Contributing:** See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and PR guidance
- **Catalog expansion:** A full walkthrough for extending the fingerprint catalog, adding version detection heuristics, and keeping the tool current is available in [GUIDE.md](GUIDE.md)
- **Security:** See [SECURITY.md](SECURITY.md) to report vulnerabilities
- **Show Support:** [Star](https://github.com/alham-rizvi/Inoue) this repo to follow along with development



## Developing

Want to contribute or run locally? See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Inoue is free and open source under the [MIT License](LICENSE).
