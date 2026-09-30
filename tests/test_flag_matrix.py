"""End-to-end CLI flag matrix for ``inoue.py``.

Every documented flag of the CLI is executed once, as a real subprocess, against
a local HTTP fixture server that this file starts on 127.0.0.1 with an
ephemeral port.  Each case asserts the process exits 0 without crashing.

Design notes
------------
* **Offline-safe by construction.**  The only host contacted on purpose is the
  127.0.0.1 fixture.  Flags that inherently reach the outside world (DNS-based
  recon, reputation, ASN, subdomain brute-force, cloud buckets, nuclei,
  screenshot, harvest-urls, crawl-katana, external-tool wrappers) are asserted
  only for *graceful* behaviour -- exit 0, no traceback, no hang -- never for a
  specific finding, and never for a particular exit code other than the one
  documented below.
* **Flag discovery is dynamic.**  The flag list is parsed out of
  ``python3 inoue.py --help`` at test time, so a newly added flag is picked up
  automatically, and :func:`test_discovered_flags_match_expected` fails loudly
  if a flag was added without updating :data:`EXPECTED_FLAGS` (the matrix would
  otherwise silently miss it).
  Only the box-drawn *option rows* of the help table are parsed.  The banner
  mentions ``inoue watch TARGET --interval 300`` and the wide-terminal rendering
  ends with an ``Examples: ... --iterations 2`` line; both are ``watch``
  subcommand options that the default command rejects with exit code 2
  ("No such option: --interval"), so they must not be treated as scan flags.
* **One documented exception to "exit 0".**  ``--fail-on-cve`` turns on CVE
  correlation (``inoue.py``: ``cve_requested = bool(cve) or fail_on_cve``) and
  exits **2** when a detected technology has a known CVE, so that flag accepts
  ``{0, 2}``.  Everything else must exit 0.
* **Scope covers an IP-literal target.**  ``--scope`` runs against the
  fixture's ``http://127.0.0.1:<port>/`` URL like every other flag: the scope
  gate matches a target by name *or* by address, so a scope file entry of
  ``127.0.0.1`` authorises it.  The out-of-scope refusal is still asserted, by
  :func:`test_scope_flag_refuses_out_of_scope_ip_literal`.
* Fixtures live in this file only -- ``tests/conftest.py`` is deliberately not
  used or modified.
"""

from __future__ import annotations

import http.server
import json
import os
import re
import subprocess
import sys
import threading
import urllib.parse
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_PATH = REPO_ROOT / "inoue.py"


def _cli_env() -> dict:
    env = dict(os.environ)
    env.setdefault("NO_COLOR", "1")
    env["TERM"] = "dumb"
    env["COLUMNS"] = "200"
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def _run_cli(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CLI_PATH), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_cli_env(),
    )

# --------------------------------------------------------------------------- #
# The fixture site
# --------------------------------------------------------------------------- #

_INDEX_HTML = b"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Flag Matrix Fixture</title>
<link rel="stylesheet" href="/style.css">
<script src="/app.js"></script>
<script src="https://cdn.jsdelivr.net/npm/x.js"></script>
</head>
<body>
<h1>Flag matrix fixture</h1>
<p>Local fixture for the Inoue CLI flag matrix.</p>
<p><a href="/about">About</a> &middot; <a href="/api/openapi.json">API</a></p>
<form action="/login" method="post"><input name="user" value="admin"></form>
</body>
</html>
"""

_ABOUT_HTML = b"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>About</title></head>
<body><h1>About</h1><p>Second page so crawling has something to follow.</p></body>
</html>
"""

# Contains a sourceMappingURL comment and an endpoint-looking string, so
# --js-intel / --exposure / --sri all have something real to chew on.
_APP_JS = b"""const apiBase = "/api/v1";
fetch(apiBase + "/health").then(function (r) { return r.json(); });
window.FIXTURE_BUILD = "flag-matrix";
//# sourceMappingURL=app.js.map
"""

# A valid source map v3 document (so a source map that *is* exposed is found).
_SOURCE_MAP = json.dumps(
    {
        "version": 3,
        "file": "app.js",
        "sources": ["app.ts"],
        "names": [],
        "mappings": "AAAA",
    }
).encode()

_STYLE_CSS = b"body { font-family: sans-serif; }\nh1 { color: #222; }\n"

_ROBOTS_TXT = b"User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml\n"

_SITEMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1/</loc></url>
  <url><loc>http://127.0.0.1/about</loc></url>
</urlset>
"""

# RFC 9116 security.txt with an Expires in the future, so it is not reported as
# expired.
_SECURITY_TXT = b"""Contact: mailto:security@example.com
Expires: 2030-01-01T00:00:00.000Z
Preferred-Languages: en
Canonical: http://127.0.0.1/.well-known/security.txt
"""

_CROSSDOMAIN_XML = b"""<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
  <allow-access-from domain="*" />
</cross-domain-policy>
"""

_OPENAPI_JSON = json.dumps(
    {
        "openapi": "3.0.0",
        "info": {"title": "Flag Matrix Fixture API", "version": "1.0.0"},
        "paths": {
            "/api/health": {
                "get": {"responses": {"200": {"description": "ok"}}},
            }
        },
    }
).encode()


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    """A small, realistic, offline site.  Anything unknown is a real 404."""

    protocol_version = "HTTP/1.1"
    server_version = "FlagMatrixFixture/1.0"
    sys_version = ""

    # keep pytest output clean
    def log_message(self, fmt, *args):  # noqa: D102 - silence BaseHTTPRequestHandler
        pass

    # -- helpers ---------------------------------------------------------- #
    def _page_headers(self):
        return [
            ("X-Powered-By", "FlagMatrix/0.1"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Referrer-Policy", "no-referrer"),
            ("Set-Cookie", "sid=fixture-session; Path=/; HttpOnly"),
            ("Alt-Svc", 'h3=":443"; ma=86400'),
        ]

    def _respond(self, status, body=b"", ctype="text/plain; charset=utf-8", extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for key, value in extra:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD" and body:
            self.wfile.write(body)

    def _drain(self):
        length = self.headers.get("Content-Length")
        if length:
            try:
                self.rfile.read(int(length))
            except (ValueError, OSError):
                pass

    # -- methods ---------------------------------------------------------- #
    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == "/":
            self._respond(200, _INDEX_HTML, "text/html; charset=utf-8", self._page_headers())
        elif path == "/about":
            self._respond(200, _ABOUT_HTML, "text/html; charset=utf-8", self._page_headers())
        elif path == "/app.js":
            self._respond(200, _APP_JS, "application/javascript", self._page_headers())
        elif path == "/app.js.map":
            self._respond(200, _SOURCE_MAP, "application/json", self._page_headers())
        elif path == "/style.css":
            self._respond(200, _STYLE_CSS, "text/css", self._page_headers())
        elif path == "/robots.txt":
            self._respond(200, _ROBOTS_TXT, "text/plain; charset=utf-8")
        elif path == "/sitemap.xml":
            self._respond(200, _SITEMAP_XML, "application/xml")
        elif path == "/.well-known/security.txt":
            self._respond(200, _SECURITY_TXT, "text/plain; charset=utf-8")
        elif path == "/crossdomain.xml":
            self._respond(200, _CROSSDOMAIN_XML, "application/xml")
        elif path == "/api/openapi.json":
            self._respond(200, _OPENAPI_JSON, "application/json")
        else:
            # A real 404, deliberately *not* a 200 catch-all: a 200 catch-all
            # would create false positives for every content-discovery module.
            self._respond(404, b"not found\n", "text/plain; charset=utf-8")

    def do_HEAD(self):
        self.do_GET()

    def do_OPTIONS(self):
        self._respond(
            200,
            b"",
            "text/plain; charset=utf-8",
            [
                ("Allow", "GET, HEAD, POST, OPTIONS"),
                ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ],
        )

    def do_POST(self):
        self._drain()
        body = b'{"ok": true}'
        self._respond(200, body, "application/json")


class _FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_fixture_site():
    """Start the fixture on an ephemeral 127.0.0.1 port.

    Returns ``(base_url, server, thread)``.
    """
    server = _FixtureServer(("127.0.0.1", 0), _FixtureHandler)
    port = server.server_address[1]
    thread = threading.Thread(
        target=server.serve_forever, name="inoue-flag-fixture", daemon=True
    )
    thread.start()
    return f"http://127.0.0.1:{port}/", server, thread


@pytest.fixture(scope="session")
def fixture_site():
    """Session-scoped fixture site; torn down even if tests fail."""
    base_url, server, thread = start_fixture_site()
    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# --------------------------------------------------------------------------- #
# Flag discovery (dynamic, so the matrix cannot silently miss a new flag)
# --------------------------------------------------------------------------- #

_FLAG_TOKEN_RE = re.compile(r"^-{1,2}[A-Za-z0-9][A-Za-z0-9-]*$")
_TYPE_TOKEN_RE = re.compile(r"^<(?:str|int|float)>$")

# Flags that take a value, mapped to the value the matrix supplies.
VALUE_FLAGS = {
    "--list",
    "--timeout",
    "--output",
    "--nuclei-out",
    "--workers",
    "--rate-limit",
    "--cache-path",
    "--cache-ttl",
    "--plugin-dir",
    "--api-key",
    "--module",
    "--cve-min-severity",
    "--crawl",
    "--js-intel-bundles",
    "--scope",
    "--history-path",
    "--nuclei-severity",
    "--screenshot-dir",
    "--webhook-url",
    "--webhook-format",
}


def _help_text() -> str:
    proc = _run_cli(["--help"], timeout=90)
    assert proc.returncode == 0, f"`--help` exited {proc.returncode}: {proc.stderr[-800:]}"
    return proc.stdout + proc.stderr


def _option_rows(help_text: str) -> list[list[str]]:
    """Tokenised rows of every box-drawn table in the help output.

    The help renders as box tables (``│ ... │``); only those rows are parsed, so
    free text outside them cannot contribute phantom flags.  This matters: the
    banner mentions ``inoue watch TARGET --interval 300`` and the wide-terminal
    rendering ends with an ``Examples: ... --iterations 2`` line -- both are
    *watch* subcommand options that the default command rejects with exit 2
    ("No such option: --interval").
    """
    rows: list[list[str]] = []
    for line in help_text.splitlines():
        if "\u2502" not in line and "|" not in line:
            continue
        inner = line.replace("\u2502", "|").strip().strip("|").strip()
        if inner:
            rows.append(inner.split())
    return rows


def _row_flags(tokens: list[str]) -> tuple[list[str], bool]:
    """Flags in a row's flag column, and whether the row takes a value.

    Only *leading* flag tokens count.  Scanning stops at the first token that is
    neither a flag nor a value type, which is the description column -- so a flag
    merely mentioned in prose (``... analyze with --js-intel``) is never
    mistaken for a declared flag, while secondary forms such as
    ``--cache --no-cache`` are both collected.
    """
    flags: list[str] = []
    takes_value = False
    for token in tokens:
        if _FLAG_TOKEN_RE.match(token):
            flags.append(token)
        elif _TYPE_TOKEN_RE.match(token):
            takes_value = True
            break
        else:
            break
    return flags, takes_value


def _discover_flags() -> list[str]:
    raw: set[str] = set()
    for tokens in _option_rows(_help_text()):
        row_flags, _ = _row_flags(tokens)
        raw.update(row_flags)
    # --help proves the Options table was actually parsed.
    assert "--help" in raw, "could not parse the Options table out of `inoue.py --help`"
    return sorted(flag for flag in raw if flag.startswith("--") and flag != "--help")


def _value_flags_from_help() -> set[str]:
    """Flags whose help row advertises a <str>/<int>/<float> value."""
    found: set[str] = set()
    for tokens in _option_rows(_help_text()):
        row_flags, takes_value = _row_flags(tokens)
        if takes_value:
            found.update(flag for flag in row_flags if flag.startswith("--"))
    return found


# Evaluated at import time: the matrix always tracks the real CLI.
DISCOVERED_FLAGS = _discover_flags()

# Baked-in snapshot of the real current output of `inoue.py --help`.  The
# equality test below fails if the CLI gains/loses a flag without this list
# (and VALUE_FLAGS) being updated.
EXPECTED_FLAGS = [
    "--active",
    "--active-ports",
    "--active-subdomains",
    "--all",
    "--api-discovery",
    "--api-key",
    "--asn",
    "--cache",
    "--cache-path",
    "--cache-ttl",
    "--check-takeover",
    "--cloud-buckets",
    "--company",
    "--crawl",
    "--crawl-katana",
    "--cve",
    "--cve-min-severity",
    "--dns",
    "--dns-deep",
    "--email-auth",
    "--email-security",
    "--evidence",
    "--exposure",
    "--extra",
    "--fail-on-cve",
    "--fast",
    "--full-recon",
    "--harvest-urls",
    "--headers",
    "--history-path",
    "--http-methods",
    "--http-protocol",
    "--js-intel",
    "--js-intel-bundles",
    "--json",
    "--list",
    "--mail",
    "--module",
    "--no-banner",
    "--no-cache",
    "--no-cve",
    "--no-dns",
    "--no-ssl",
    "--nuclei",
    "--nuclei-out",
    "--nuclei-severity",
    "--output",
    "--passive",
    "--plugin-dir",
    "--ports",
    "--rate-limit",
    "--reputation",
    "--save-history",
    "--scope",
    "--screenshot",
    "--screenshot-dir",
    "--service",
    "--smart",
    "--sri",
    "--ssl",
    "--subdomain-brute",
    "--subdomains",
    "--timeout",
    "--tls-fingerprint",
    "--verbose",
    "--vhost",
    "--webhook-format",
    "--webhook-url",
    "--whois",
    "--workers",
]

# --------------------------------------------------------------------------- #
# Per-flag subprocess budget (seconds)
# --------------------------------------------------------------------------- #
# Generous but finite: a hang must fail the test rather than stall the suite.
# Everything not listed uses DEFAULT_TIMEOUT.  The values below are ~4x the
# measured runtime against the local fixture; the external-tool wrappers get the
# largest budgets because they may legitimately run nuclei / katana / naabu /
# subfinder against 127.0.0.1 when those binaries are on PATH.
DEFAULT_TIMEOUT = 90
TIMEOUT_BUDGETS = {
    "--all": 240,
    "--active": 180,
    "--active-ports": 180,
    "--active-subdomains": 240,
    "--cloud-buckets": 120,
    "--company": 120,
    "--crawl-katana": 180,
    "--dns-deep": 120,
    "--email-auth": 120,
    "--exposure": 120,
    "--extra": 120,
    "--fail-on-cve": 120,
    "--full-recon": 240,
    "--harvest-urls": 180,
    "--nuclei": 300,
    "--passive": 120,
    "--ports": 120,
    "--reputation": 120,
    "--screenshot": 120,
    "--subdomain-brute": 120,
    "--subdomains": 120,
    "--vhost": 120,
    "--whois": 120,
}

# --fail-on-cve enables CVE correlation and exits 2 when a CVE is found.
_EXIT_CODE_EXCEPTIONS = {"--fail-on-cve": (0, 2)}

_CRASH_MARKERS = (
    "Traceback (most recent call last)",
    "TypeError",
    "Unhandled exception",
)


def _value_for(flag: str, tmp_path: Path, base_url: str) -> str:
    """The value supplied for a value-taking flag, and why.

    All paths point under ``tmp_path`` so the matrix never writes into the repo;
    the two URL values point at the local fixture so nothing leaves the host.
    """
    if flag == "--list":
        # One target per line, as documented.
        target_list = tmp_path / "targets.txt"
        target_list.write_text(base_url + "\n", encoding="utf-8")
        return str(target_list)
    if flag == "--timeout":
        return "5"  # keep every request budget short
    if flag == "--output":
        return str(tmp_path / "scan.json")  # Save JSON to file
    if flag == "--nuclei-out":
        return str(tmp_path / "nuclei-groups.json")
    if flag == "--workers":
        return "2"
    if flag == "--rate-limit":
        return "10"  # requests per second per host
    if flag == "--cache-path":
        return str(tmp_path / "cache.db")
    if flag == "--cache-ttl":
        return "60"
    if flag == "--plugin-dir":
        plugins = tmp_path / "plugins"
        plugins.mkdir(exist_ok=True)  # empty dir: no third-party plugins
        return str(plugins)
    if flag == "--api-key":
        return "flag-matrix-test-key"  # synthetic; enrichment must degrade offline
    if flag == "--module":
        return "fast"  # a real preset that needs no external tooling
    if flag == "--cve-min-severity":
        return "high"
    if flag == "--crawl":
        return "1"  # fetch one extra same-origin page
    if flag == "--js-intel-bundles":
        return "1"
    if flag == "--scope":
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text(
            "# flag-matrix fixture scope\n127.0.0.1\nlocalhost\n", encoding="utf-8"
        )
        return str(scope_file)
    if flag == "--history-path":
        return str(tmp_path / "history.db")
    if flag == "--nuclei-severity":
        return "high,critical"
    if flag == "--screenshot-dir":
        shots = tmp_path / "screenshots"
        shots.mkdir(exist_ok=True)
        return str(shots)
    if flag == "--webhook-url":
        return base_url + "webhook"  # local fixture, so delivery stays offline
    if flag == "--webhook-format":
        return "generic"
    raise AssertionError(f"no value documented for value-taking flag {flag}")


def _target_for(flag: str, base_url: str) -> str:
    """The target URL for one flag's matrix case: the fixture's 127.0.0.1 URL.

    ``--scope`` used to be overridden to ``localhost`` because the scope gate
    matched the *hostname* only, so an IP-literal target could never satisfy an
    IP/CIDR entry in a scope file and was refused with exit 1.  The gate now also
    matches the target's address, so ``--scope`` exercises the same IP-literal
    URL as every other flag; the graceful refusal path for a genuinely
    out-of-scope address is asserted by
    :func:`test_scope_flag_refuses_out_of_scope_ip_literal`.
    """
    return base_url


def _argv_for(flag: str, tmp_path: Path, base_url: str) -> list[str]:
    target = _target_for(flag, base_url)
    if flag in VALUE_FLAGS:
        return ["--no-banner", flag, _value_for(flag, tmp_path, base_url), "--json", target]
    return ["--no-banner", flag, "--json", target]


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_help_exits_zero_and_prints_usage():
    proc = _run_cli(["--help"], timeout=90)
    assert proc.returncode == 0
    combined = proc.stdout + proc.stderr
    assert "Usage" in combined
    assert "--module" in combined


def test_discovered_flags_match_expected():
    """Adding a CLI flag without updating the matrix must fail here."""
    assert DISCOVERED_FLAGS == sorted(EXPECTED_FLAGS), (
        "the CLI flag set changed; update EXPECTED_FLAGS (and VALUE_FLAGS) "
        f"in this file.\n  only in help: {sorted(set(DISCOVERED_FLAGS) - set(EXPECTED_FLAGS))}\n"
        f"  only in EXPECTED_FLAGS: {sorted(set(EXPECTED_FLAGS) - set(DISCOVERED_FLAGS))}"
    )


def test_value_flags_match_help():
    """Every flag whose help row shows <str>/<int>/<float> must have a value."""
    from_help = _value_flags_from_help()
    assert from_help == VALUE_FLAGS, (
        "value-taking flags drifted from the matrix.\n"
        f"  help says: {sorted(from_help)}\n  matrix says: {sorted(VALUE_FLAGS)}"
    )


def test_json_output_is_a_real_result(fixture_site):
    """Sanity: the fixture is actually scanned, so exit 0 means something."""
    proc = _run_cli(["--no-banner", "--json", fixture_site], timeout=120)
    assert proc.returncode == 0, proc.stderr[-800:]
    payload = json.loads(proc.stdout)
    assert isinstance(payload, list) and payload, "expected a JSON array of results"
    result = payload[0]
    assert result["status_code"] == 200, result
    assert "127.0.0.1" in result["url"]
    # The fixture's distinctive headers must be visible to header analysis.
    headers = {k.lower(): v for k, v in (result.get("headers") or {}).items()}
    assert headers.get("x-powered-by") == "FlagMatrix/0.1"


@pytest.mark.parametrize("flag", DISCOVERED_FLAGS, ids=lambda f: f.lstrip("-"))
def test_flag_runs_end_to_end(flag, fixture_site, tmp_path):
    """Every CLI flag must run to completion without crashing."""
    budget = TIMEOUT_BUDGETS.get(flag, DEFAULT_TIMEOUT)
    argv = _argv_for(flag, tmp_path, fixture_site)

    try:
        proc = _run_cli(argv, timeout=budget)
    except subprocess.TimeoutExpired:
        pytest.fail(f"{flag} did not finish within {budget}s (argv={argv})")

    combined = proc.stdout + proc.stderr
    for marker in _CRASH_MARKERS:
        assert marker not in combined, (
            f"{flag} produced a crash marker {marker!r}\n"
            f"argv={argv}\nrc={proc.returncode}\n"
            f"stdout={proc.stdout[-1500:]}\nstderr={proc.stderr[-1500:]}"
        )

    allowed = _EXIT_CODE_EXCEPTIONS.get(flag, (0,))
    assert proc.returncode in allowed, (
        f"{flag} exited {proc.returncode}, expected one of {allowed}\n"
        f"argv={argv}\nstdout={proc.stdout[-1500:]}\nstderr={proc.stderr[-1500:]}"
    )


def test_combined_recon_flags_in_one_invocation(fixture_site, tmp_path):
    """The new recon flags must coexist in a single invocation."""
    argv = [
        "--no-banner",
        "--dns-deep",
        "--email-auth",
        "--exposure",
        "--subdomain-brute",
        "--sri",
        "--json",
        fixture_site,
    ]
    proc = _run_cli(argv, timeout=420)
    combined = proc.stdout + proc.stderr
    for marker in _CRASH_MARKERS:
        assert marker not in combined, f"combined recon run crashed: {proc.stderr[-1500:]}"
    assert proc.returncode == 0, f"combined recon run exited {proc.returncode}"
    payload = json.loads(proc.stdout)
    assert payload and payload[0]["status_code"] == 200


def test_scope_flag_allows_in_scope_ip_literal(fixture_site, tmp_path):
    """A scope file entry of ``127.0.0.1`` must authorise the IP-literal
    target ``http://127.0.0.1:<port>/``.

    The entry parses as a ``127.0.0.1/32`` network, not as a domain, so it can
    only ever match through the address check.  Regression guard: this used to
    be refused outright, which meant ``--scope`` could not cover the very
    address its own file named.
    """
    scope_file = tmp_path / "ip-only-scope.txt"
    scope_file.write_text("127.0.0.1\n", encoding="utf-8")
    proc = _run_cli(
        ["--no-banner", "--scope", str(scope_file), "--json", fixture_site], timeout=90
    )
    combined = proc.stdout + proc.stderr
    for marker in _CRASH_MARKERS:
        assert marker not in combined, proc.stderr[-1200:]
    assert proc.returncode == 0, f"in-scope IP literal was refused: {proc.stdout[-800:]}"
    payload = json.loads(proc.stdout)
    assert not payload[0].get("error"), payload[0].get("error")
    assert payload[0]["status_code"] == 200, payload[0]


def test_scope_flag_refuses_out_of_scope_ip_literal(fixture_site, tmp_path):
    """The refusal for a genuinely out-of-scope address stays graceful.

    "Refuses to scan any target not in scope before making any request" is the
    documented behaviour, so assert it explicitly rather than hiding it in an
    exit-code allow-list.
    """
    scope_file = tmp_path / "out-of-scope.txt"
    scope_file.write_text("10.99.0.0/16\n", encoding="utf-8")
    proc = _run_cli(
        ["--no-banner", "--scope", str(scope_file), "--json", fixture_site], timeout=90
    )
    combined = proc.stdout + proc.stderr
    for marker in _CRASH_MARKERS:
        assert marker not in combined, proc.stderr[-1200:]
    assert proc.returncode == 1, f"expected the documented refusal, got {proc.returncode}"
    payload = json.loads(proc.stdout)
    assert "not in scope" in (payload[0].get("error") or "")
    assert payload[0]["status_code"] == 0  # no request was made


@pytest.mark.parametrize("preset", ["full-recon", "fast"])
def test_module_presets_run(preset, fixture_site):
    argv = ["--no-banner", "-m", preset, "--json", fixture_site]
    budget = TIMEOUT_BUDGETS.get("--full-recon" if preset == "full-recon" else "--fast", 480)
    proc = _run_cli(argv, timeout=budget)
    combined = proc.stdout + proc.stderr
    for marker in _CRASH_MARKERS:
        assert marker not in combined, f"-m {preset} crashed: {proc.stderr[-1500:]}"
    assert proc.returncode == 0, f"-m {preset} exited {proc.returncode}"
    payload = json.loads(proc.stdout)
    assert payload and payload[0]["status_code"] == 200
