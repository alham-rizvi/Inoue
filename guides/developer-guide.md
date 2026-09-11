# Inoue developer guide

This guide is for engineers, maintainers, and contributors who want to understand how Inoue works internally and how to extend the project safely.

## Project purpose

Inoue is a read only reconnaissance and technology fingerprinting tool. It identifies technologies that are visible on a target site or service and improves the output with evidence, confidence, and optional CVE correlation.

The tool is designed for:

- recon and footprinting
- security review workflows
- bug bounty and tooling support
- product and technology mapping
- documentation generation and reporting

## Repository map

This is the main layout:

```text
Inoue/
├── api/
│   └── main.py                 # FastAPI backend
├── core/
│   ├── cache.py                # SQLite cache
│   ├── config.py               # config precedence and defaults
│   ├── cve.py                  # local CVE matching
│   ├── plugins.py              # plugin lifecycle and error handling
│   ├── scanner.py              # main detection engine
│   ├── terminal.py             # Rich/terminal configuration
│   └── tls_fingerprint.py      # optional TLS metadata support
├── data/
│   └── cves.json               # local CVE dataset
├── extension/
│   ├── assets/
│   ├── background.js           # browser background logic
│   ├── manifest.json           # browser extension manifest
│   ├── popup.css               # extension styles
│   ├── popup.html              # popup UI
│   └── popup.js                # UI behavior
├── fingerprints/
│   ├── extended_catalog.py     # extra signatures
│   ├── signatures.py           # primary catalog
│   └── web_server_catalog.py   # server family signatures
├── guides/
│   ├── architecture.md         # architecture overview
│   ├── cli-reference.md        # command docs
│   ├── installation.md         # install and setup
│   ├── developer-guide.md      # contributor guide
│   └── README.md               # guide index
├── scripts/
│   ├── audit_signatures.py     # provenance audit helper
│   ├── build_extension.py      # extension packaging
│   ├── check_signatures.py     # duplicate signature audits
│   └── import_wappalyzer.py    # import flow for external catalog work
├── tests/
│   ├── fixtures/               # regression fixtures
│   ├── test_api.py             # API validation
│   ├── test_extension.py       # extension release tests
│   ├── test_roadmap_features.py # roadmap and feature tests
│   ├── test_scanner.py         # scanner regression tests
│   └── test_signature_fixtures.py # fixture-based catalog tests
├── inoue.py                    # CLI entry point
├── mcp_server.py               # optional MCP adapter
├── README.md                  # top level project landing page
├── API.md                     # API docs
├── COMMANDS.md                # command overview
├── CODEBASE_GUIDE.md          # architecture and conventions
├── GUIDE.md                   # extension and updater guide
├── pyproject.toml             # package metadata and scripts
├── requirements.txt           # dev and runtime dependencies
├── SECURITY.md                # security policy
├── Dockerfile                 # container definition
├── docker-compose.yml         # container orchestration
└── TODO.md                    # roadmap and backlog
```

## Starting points for contributors

If you are making a change, start with one of these files:

- `inoue.py` for CLI behavior
- `core/scanner.py` for detection logic
- `fingerprints/signatures.py` for catalog rules
- `api/main.py` for API behavior
- `extension/popup.js` for browser UI behavior

## Development workflow

Use a clean virtual environment and install the repo in editable mode:

```bash
git clone https://github.com/alham-rizvi/Inoue.git
cd Inoue
python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Then validate the repo with the required suite:

```bash
python -m pytest tests/ -q
python -m pytest tests/ -q -W error
```

The project expects this validation before and after substantive changes.

## How a scan works

The basic flow is:

1. user provides a target
2. CLI resolves config and flags
3. scanner calls the HTTP client
4. scanner normalizes host and URL states
5. scanner builds candidate signatures
6. catalog entries are matched against headers, scripts, cookies, HTML, and paths
7. recon modules optionally enrich the result with DNS, SSL, WHOIS, subdomains, ports, and public intel
8. CVE matching and plugins run if enabled
9. final result is rendered or serialized

This is the core data flow behind the entire tool.

## Adding a new signature

Adding a signature is usually the safest way to improve coverage. Keep the change narrow and testable.

### Good pattern

- add one signature to the catalog
- use a specific regex or path pattern
- include a fixture in `tests/fixtures`
- update or add one regression test
- validate with the test suite

### Avoid

- broad substring matches on generic page text
- overbroad regexes that match unrelated content
- changing scanner logic without a corresponding test

## Version detection rules

Version detection should be specific and conservative.

Prefer:

- explicit version strings in headers
- numeric versions in script URLs or HTML markers
- clear product version patterns

Avoid:

- random timestamp values
- Vercel or trace identifiers that are not versions
- body copy or generic marketing text that happens to include a product name

## False positive handling

The scanner has protections for common false positives:

- exclusion rules for generic or conflicting matches
- contradiction notes for multiple server-family matches
- explicit OS detection restrictions for HTML body copy
- stable confidence scoring based on signal agreement

This is especially important because recon tools are highly vulnerable to noisy page content.

## Testing strategy

Use the real test suite, not mock-only assertions.

The project includes a large set of coverage areas:

- scanner detection
- CLI output contract
- API request validation
- extension packaging
- fixture-based signature use
- cache behavior
- CVE matching

The main command to use is:

```bash
python -m pytest tests/ -q
```

Use the strict warning version during deeper verification:

```bash
python -m pytest tests/ -q -W error
```

## Contribution standards

When contributing code:

- keep changes focused and small
- add or update a test for the behavior
- avoid broad rewrites without justification
- document user facing behavior if flags or outputs change
- keep the project read only and recon oriented

## Release and packaging notes

The Python package is exposed via the project script entry point. The global command is the public contract for users.

Relevant files:

- `pyproject.toml`
- `README.md`
- `COMMANDS.md`
- `API.md`
- `scripts/build_extension.py`

## Summary

Inoue is designed to be stable, explainable, and modular. The strongest pattern in the project is a single scanner core that powers the CLI, API, and extension. That keeps the project consistent, reduces duplicate logic, and makes adding or verifying new detections easier.
