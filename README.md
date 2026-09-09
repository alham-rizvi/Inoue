# Inoue

<img width="430" height="63" alt="image" src="https://github.com/user-attachments/assets/3ebec879-7fdb-4ee4-9def-277e95b1c406" />

Inoue is a fast, open-source recon-oriented tech stack fingerprinting CLI. It is designed to identify the technologies exposed by a target website or service from the terminal, with a broad signature catalog that covers servers, runtimes, CMS platforms, ecommerce stacks, frameworks, JavaScript libraries, analytics tools, payment providers, admin panels, cloud/self-hosted management surfaces, VPN portals, and IoT/admin devices.

It is useful for recon, CTF/HTB, bug bounty, internal network review, and general surface analysis.

Maintained by Alham Rizvi.

Repository: https://github.com/alhamrizvi-cloud/Inoue

## Features

- Broad fingerprint coverage for web servers, languages, frameworks, CMS, ecommerce platforms, JS libraries, analytics, payments, CDNs, WAFs, and more
- An expanded catalog with 600+ services, cloud portals, ICS/SCADA surfaces, admin panels, network appliances, and self-hosted platforms
- Detection from HTTP headers, cookies, HTML, script tags, meta tags, and URL paths
- Recon-oriented service hints for exposed admin panels, management consoles, cloud portals, and self-hosted applications
- Version-aware detection where the signature supports it
- SSL/TLS inspection with certificate metadata and handshake details
- DNS intelligence for A, AAAA, MX, NS, TXT, and CNAME records
- Security header auditing for HSTS, CSP, X-Frame-Options, and related protections
- Parallel scanning for multiple targets with configurable worker count
- Structured JSON output for automation and reporting
- Rich CLI output with confidence, version, and evidence hints
- Live scan progress and discovery logging for each target
- Extensible signature engine for quickly adding new detections
  
<img width="797" height="733" alt="image" src="https://github.com/user-attachments/assets/e2101e22-1391-4056-a98a-d65f1a6f8a5f" />


## Install

```bash
git clone https://github.com/alhamrizvi-cloud/Inoue.git
cd Inoue
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python inoue.py example.com

# Verbose scan with SSL, DNS, headers, and security inspection
python inoue.py -v target.htb

# Show the evidence behind each detection
python inoue.py -e https://target.com

# Full recon-style scan
python inoue.py -v -e https://target.com

# Scan multiple targets concurrently
python inoue.py site1.com site2.com site3.com

# Read targets from a file or stdin pipeline
python inoue.py --list targets.txt
cat targets.txt | python inoue.py --json

# Rate-limit and cache repeat scans
python inoue.py --rate-limit 1 --cache target.com

# Correlate detected versions with the local CVE dataset
python inoue.py --cve target.com
python inoue.py --cve --cve-min-severity high target.com

# Refresh the local CVE dataset explicitly
python inoue.py update-cve

# Export technology-tagged URLs for downstream nuclei workflows
python inoue.py --nuclei-out nuclei-targets.json target.com

# JSON output
python inoue.py --json target.com
python inoue.py --json -o results.json target.com
python inoue.py -o report.html target.com

# Fast HTB/CTF style scan without DNS
python inoue.py --no-dns -t 5 10.10.11.55

# Skip SSL checks for HTTP-only or self-signed targets
python inoue.py --no-ssl http://target.htb

# Pull the latest catalog and scanner updates from the repository
python inoue.py update
```

For a full command reference, see [COMMANDS.md](COMMANDS.md).

Operational defaults can be stored in project `.inoue.toml` or user
`~/.config/inoue/config.toml`; CLI flags always take precedence.

## Options

| Flag | Description |
|------|-------------|
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

- Web servers: Apache, Nginx, IIS, LiteSpeed, Caddy, Tomcat, OpenResty
- Languages and runtimes: PHP, ASP.NET, Node.js, Python, Ruby on Rails, Java, Go
- Frameworks: Laravel, Django, Flask, Express.js, Spring, Symfony, FastAPI, Next.js, React, Vue, Angular
- CMS and ecommerce: WordPress, Drupal, Joomla, Magento, Shopify, PrestaShop, OpenCart, Ghost
- Analytics and marketing: Google Analytics, Tag Manager, Hotjar, Matomo, Plausible, Segment, Mixpanel
- Payments: Stripe, PayPal, Braintree, Authorize.Net, Square, Adyen, Paddle
- CDNs and security: Cloudflare, CloudFront, Fastly, Akamai, Varnish, WAF products
- Admin and management panels: phpMyAdmin, Adminer, pgAdmin, Webmin, Portainer, Jenkins, GitLab, Jira, Confluence, Webmin, and more
- Cloud and self-hosted infrastructure: OpenStack, OpenShift, Proxmox, oVirt, CloudStack, Rancher, Harbor, Nextcloud, OwnCloud
- VPN and remote access: OpenVPN, WireGuard, Tailscale, pfSense, OPNsense, FortiGate, UniFi, MikroTik
- IoT and appliance surfaces: Home Assistant, OpenHAB, Synology DSM, QNAP QTS, TrueNAS, routers, cameras, and printer web consoles

## How detection works

The scanner evaluates several signal sources in order:

- HTTP response headers
- Cookies
- HTML body content
- Script tags and referenced assets
- Meta tags
- URL paths and common login/admin routes

Each detection is enriched with a confidence level, version hint when available, and evidence from the matched signal.

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for setup and PR guidance.

## Catalog expansion and update guide

A full walkthrough for extending the fingerprint catalog, adding version detection heuristics, and keeping the tool current is available in [GUIDE.md](GUIDE.md).

Normalize a reviewed Wappalyzer catalog without changing scans:

```bash
python scripts/import_wappalyzer.py wappalyzer.json
python scripts/import_wappalyzer.py wappalyzer.json --write --output imported.json
```

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

## License

This project is licensed under a proprietary freelance license. All rights are reserved by the copyright holder. Unauthorized copying, redistribution, modification, commercial use, or publication is prohibited without written permission.

See [LICENSE](LICENSE) for the full text.
