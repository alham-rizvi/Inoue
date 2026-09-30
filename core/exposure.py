# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Sensitive-artefact and client-side exposure probing against a web root.

A short, fixed list of paths covers the vast majority of "forgot to remove it"
exposures: a checked-out ``.git`` directory that serves its own HEAD and config,
an ``.env`` file with live credentials, an ``.svn`` working copy, database
dumps and archives left in the web root, editor backups of PHP sources, lock
files that pin exact dependency versions, ``phpinfo()`` output and Apache's
``server-status``. Each is a single anonymous GET to a path any visitor could
request, so this is recon rather than exploitation.

THE FALSE POSITIVE PROBLEM, AND HOW IT IS HANDLED. A bare HTTP 200 is
worthless as evidence here: modern SPAs, single-page routers, CDN error pages
and "soft 404" handlers answer 200 with an HTML shell for literally every path.
Reporting "file exposed" off a status code alone is how scanners earn a
reputation for noise. So every 200 must pass a content check that proves the
response really is the artefact:

  * /.git/HEAD          body must begin with ``ref:`` (e.g. ``ref: refs/heads/main``)
  * /.git/config        body must contain ``[core]`` or ``repositoryformatversion``
  * /.env, /.env.local  body must look like dotenv: >=2 ``KEY=VALUE`` lines, and
                        must not be an HTML document
  * /.svn/entries       Subversion entries shape (revision line + ``dir``) or a
                        SQLite header for ``wc.db``; never an HTML shell
  * /.DS_Store          must carry the ``Bud1`` magic bytes
  * *.zip / *.tar.gz    must carry the ZIP (``PK\\x03\\x04``) or gzip (``\\x1f\\x8b``)
                        magic prefix; otherwise it is not an archive at all
  * *.sql               must contain real SQL (INSERT/CREATE TABLE/comment) and
                        must not be an HTML document
  * *.php.bak           must contain PHP source (``<?php``/``<?=``)
  * /composer.lock      must parse as JSON with composer's own top-level keys
  * /package-lock.json  must parse as JSON with npm's lockfile keys
  * /web.config         must look like IIS XML configuration, not an HTML shell
  * /.htaccess          must be non-HTML; a lone "Not Found" line is rejected
  * /phpinfo.php        must contain ``phpinfo()`` or ``PHP Version``
  * /server-status      must contain ``Apache Server Status``

A 200 that fails its check is NOT a finding. It is recorded under
``candidates`` with a note explaining why it could not be verified, so the
distinction between "this really is the file" and "the server answers 200 for
everything" is explicit and auditable in the returned data. Findings are also
gated on the DNS/transport layer succeeding: an absent ``security.txt`` is only
reported when both well-known locations gave a definitive (non-error) answer.

Two adjacent checks ride along because they need no extra machinery:
  * ``security.txt`` (RFC 9116) is parsed into its ``Key: value`` fields; a
    missing file or an ``Expires`` date already in the past is a genuinely
    reportable hygiene finding, not an exposure.
  * ``crossdomain.xml`` is parsed with ``defusedxml`` (never the stdlib
    parser) and flagged only for the dangerous ``<allow-access-from domain="*"/>``
    wildcard.
  * Published JavaScript source maps are inferred from the base page's own
    same-origin ``<script src>`` and stylesheet links; a ``.map`` that returns
    200 and parses as a valid source map hands over the original, unminified
    source and is reported.

Every request is individually wrapped, uses a short timeout and a fixed
browser-ish User-Agent, and the probe set is bounded by ``max_paths`` (list
order is priority order) with the source-map section additionally capped and
skippable via ``fetch_source_maps=False``. One extra request fetches the base
page itself so directory-listing detection has something real to inspect; it is
not counted in ``checked``, which counts list paths only.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

import httpx

try:  # declared dependency; guarded so importing this module can never raise
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - defensive
    BeautifulSoup = None

try:  # declared dependency; guarded so importing this module can never raise
    import defusedxml.ElementTree as _DET
except ImportError:  # pragma: no cover - defensive
    _DET = None

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_MAX_BODY_BYTES = 524_288
_SOURCE_MAP_LIMIT = 5

_SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")
_CROSSDOMAIN_PATH = "/crossdomain.xml"
# Present on any healthy site and therefore never interesting on their own.
_QUIET_PATHS = ("/robots.txt", "/sitemap.xml")

# The probe list, in the required priority order. Only the first `max_paths`
# entries are ever requested.
_PATHS = [
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.svn/entries",
    "/.DS_Store",
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/dump.sql",
    "/index.php.bak",
    "/config.php.bak",
    "/web.config",
    "/composer.lock",
    "/package-lock.json",
    "/.htaccess",
    "/phpinfo.php",
    "/server-status",
    "/.well-known/security.txt",
    "/security.txt",
    "/crossdomain.xml",
    "/robots.txt",
    "/sitemap.xml",
]

_HTML_RE = re.compile(r"<\s*html|<!doctype", re.IGNORECASE)
_DOTENV_LINE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", re.MULTILINE)
_SQL_RE = re.compile(
    r"(insert\s+into|create\s+table|drop\s+table|alter\s+table|copy\s+\w+\s+from|"
    r"pragma\s+|mysqldump|--\s|/\*)",
    re.IGNORECASE,
)
_SVN_ENTRIES_RE = re.compile(r"^\s*\d+\s*\ndir\s*\n")
_HTACCESS_TOKENS = (
    "rewriteengine",
    "rewriterule",
    "rewritecond",
    "order ",
    "deny from",
    "allow from",
    "<ifmodule",
    "options ",
    "require ",
    "php_value",
    "php_flag",
    "header set",
    "setenv",
    "errordocument",
    "addtype",
    "directoryindex",
)
_SECURITY_TXT_KNOWN_FIELDS = (
    "contact",
    "expires",
    "policy",
    "canonical",
    "preferred-languages",
    "languages",
    "encryption",
    "acknowledgments",
    "hiring",
)


def _text_of(response: httpx.Response) -> str:
    """Decode a bounded prefix of the body as text (never raises)."""
    try:
        return response.content[:_MAX_BODY_BYTES].decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return ""


def _raw_of(response: httpx.Response) -> bytes:
    try:
        return response.content[:_MAX_BODY_BYTES]
    except Exception:  # pragma: no cover - defensive
        return b""


def _evidence(text: str, limit: int = 240) -> str:
    """Collapse whitespace and truncate a body snippet for the report."""
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


def _is_html(text: str) -> bool:
    return bool(_HTML_RE.search(text or ""))


# --------------------------------------------------------------------------
# Per-artefact content verifiers.
#
# Each takes the decoded text plus the raw bytes and returns (verified, detail).
# A False return means "this is not credibly the artefact" and routes the 200
# into `candidates` rather than `findings`.
# --------------------------------------------------------------------------
def _v_git_head(text: str, raw: bytes) -> tuple[bool, str]:
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("ref:"):
        return True, f"git HEAD ref served: {stripped.splitlines()[0].strip()}"
    return False, "HTTP 200 but body does not begin with 'ref:' - not a git HEAD file"


def _v_git_config(text: str, raw: bytes) -> tuple[bool, str]:
    low = text.lower()
    if "[core]" in low or "repositoryformatversion" in low:
        return True, "git config served ([core] / repositoryformatversion present)"
    return False, "HTTP 200 but no '[core]' or 'repositoryformatversion' - not a git config"


def _v_dotenv(text: str, raw: bytes) -> tuple[bool, str]:
    if _is_html(text):
        return False, "HTTP 200 but body is an HTML document, not dotenv content"
    assignments = _DOTENV_LINE_RE.findall(text)
    if len(assignments) >= 2:
        return True, f"dotenv content with {len(assignments)} KEY=VALUE assignments"
    return False, "HTTP 200 but fewer than two KEY=VALUE lines - not dotenv content"


def _v_svn_entries(text: str, raw: bytes) -> tuple[bool, str]:
    if raw.startswith(b"SQLite format 3\x00"):
        return True, "SQLite database served (consistent with .svn/wc.db)"
    if _is_html(text):
        return False, "HTTP 200 but body is an HTML document, not .svn/entries"
    if _SVN_ENTRIES_RE.match(text):
        return True, "Subversion entries format (revision line followed by 'dir')"
    return False, "HTTP 200 but body is not a recognizable .svn/entries file"


def _v_ds_store(text: str, raw: bytes) -> tuple[bool, str]:
    if raw.startswith(b"\x00\x00\x00\x01Bud1"):
        return True, "macOS .DS_Store magic bytes (Bud1) present"
    return False, "HTTP 200 but body lacks the .DS_Store (Bud1) magic bytes"


def _v_zip(text: str, raw: bytes) -> tuple[bool, str]:
    if raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return True, "ZIP archive magic bytes (PK\\x03\\x04) present"
    return False, "HTTP 200 but body lacks the ZIP magic bytes - not an archive"


def _v_gzip(text: str, raw: bytes) -> tuple[bool, str]:
    if raw.startswith(b"\x1f\x8b"):
        return True, "gzip archive magic bytes (\\x1f\\x8b) present"
    return False, "HTTP 200 but body lacks the gzip magic bytes - not an archive"


def _v_sql(text: str, raw: bytes) -> tuple[bool, str]:
    if _is_html(text):
        return False, "HTTP 200 but body is an HTML document, not a SQL dump"
    if _SQL_RE.search(text):
        return True, "SQL statements detected (INSERT / CREATE TABLE / comment)"
    return False, "HTTP 200 but no SQL statements detected - not a SQL dump"


def _v_php_backup(text: str, raw: bytes) -> tuple[bool, str]:
    if "<?php" in text.lower() or "<?=" in text:
        return True, "PHP source detected (<?php marker)"
    return False, "HTTP 200 but no '<?php' marker - not a PHP source backup"


def _v_web_config(text: str, raw: bytes) -> tuple[bool, str]:
    if _is_html(text):
        return False, "HTTP 200 but body is an HTML document, not web.config"
    low = text.lower()
    if "<configuration" in low or "<?xml" in low or "<system.webserver" in low:
        return True, "IIS web.config XML (<configuration>) detected"
    return False, "HTTP 200 but no <configuration> XML root - not web.config"


def _v_htaccess(text: str, raw: bytes) -> tuple[bool, str]:
    if _is_html(text):
        return False, "HTTP 200 but body is an HTML document, not .htaccess"
    low = text.lower()
    if any(token in low for token in _HTACCESS_TOKENS):
        return True, "Apache .htaccess directives detected"
    if "\n" in text.strip():
        return True, "multi-line plain-text served for .htaccess (no HTML shell)"
    return False, "single-line non-HTML body - not confidently an .htaccess file"


def _v_composer_lock(text: str, raw: bytes) -> tuple[bool, str]:
    try:
        parsed = json.loads(text)
    except Exception:
        return False, "HTTP 200 but body is not valid JSON"
    keys = [k for k in ("packages", "packages-dev", "content-hash", "_readme") if k in (parsed or {})]
    if keys:
        return True, f"composer.lock JSON with key(s): {', '.join(keys)}"
    return False, "valid JSON but without composer.lock keys - not a composer lockfile"


def _v_package_lock(text: str, raw: bytes) -> tuple[bool, str]:
    try:
        parsed = json.loads(text)
    except Exception:
        return False, "HTTP 200 but body is not valid JSON"
    keys = [k for k in ("lockfileVersion", "packages", "dependencies") if k in (parsed or {})]
    if keys:
        return True, f"npm package-lock JSON with key(s): {', '.join(keys)}"
    return False, "valid JSON but without npm lockfile keys - not a package-lock"


def _v_phpinfo(text: str, raw: bytes) -> tuple[bool, str]:
    low = text.lower()
    if "phpinfo()" in low or "php version" in low:
        return True, "phpinfo() output detected"
    return False, "HTTP 200 but no 'phpinfo()' or 'PHP Version' marker"


def _v_server_status(text: str, raw: bytes) -> tuple[bool, str]:
    if "apache server status" in text.lower():
        return True, "Apache server-status page detected"
    return False, "HTTP 200 but no 'Apache Server Status' marker"


# path -> (kind, severity, verifier)
_ARTIFACTS: dict[str, tuple[str, str, Callable[[str, bytes], tuple[bool, str]]]] = {
    "/.git/HEAD": ("git_disclosure", "high", _v_git_head),
    "/.git/config": ("git_disclosure", "high", _v_git_config),
    "/.env": ("credentials", "critical", _v_dotenv),
    "/.env.local": ("credentials", "critical", _v_dotenv),
    "/.svn/entries": ("svn_disclosure", "medium", _v_svn_entries),
    "/.DS_Store": ("metadata_disclosure", "low", _v_ds_store),
    "/backup.zip": ("backup_disclosure", "high", _v_zip),
    "/backup.tar.gz": ("backup_disclosure", "high", _v_gzip),
    "/db.sql": ("database_dump", "high", _v_sql),
    "/dump.sql": ("database_dump", "high", _v_sql),
    "/index.php.bak": ("source_backup", "medium", _v_php_backup),
    "/config.php.bak": ("source_backup", "high", _v_php_backup),
    "/web.config": ("config_disclosure", "medium", _v_web_config),
    "/composer.lock": ("lockfile_disclosure", "low", _v_composer_lock),
    "/package-lock.json": ("lockfile_disclosure", "low", _v_package_lock),
    "/.htaccess": ("config_disclosure", "medium", _v_htaccess),
    "/phpinfo.php": ("info_disclosure", "high", _v_phpinfo),
    "/server-status": ("info_disclosure", "medium", _v_server_status),
}

_LISTING_MARKERS = ("index of /", "[to parent directory]", "directory listing for")


def _looks_like_listing(text: str) -> bool:
    """True only for a real autoindex page, not a page that merely mentions one."""
    low = (text or "").lower()
    if "index of /" in low and "href=" in low:
        return True
    if "[to parent directory]" in low:
        return True
    if "directory listing for" in low and "href=" in low:
        return True
    return False


def _parse_security_txt(text: str) -> dict:
    """Parse RFC 9116 ``Key: value`` lines into a dict (lists when repeated)."""
    fields: dict = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not key or not value:
            continue
        if key in fields:
            existing = fields[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                fields[key] = [existing, value]
        else:
            fields[key] = value
    return fields


def _looks_like_security_txt(fields: dict) -> bool:
    """Require at least one RFC 9116 field so an arbitrary JSON/text blob is out."""
    return any(key.lower() in _SECURITY_TXT_KNOWN_FIELDS for key in fields)


def _is_expired(value: Optional[object]) -> bool:
    """True when an Expires value parses and lies in the past. Unparseable -> False."""
    if not value:
        return False
    raw = value[0] if isinstance(value, list) else value
    if not isinstance(raw, str):
        return False
    normalised = raw.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalised)
    except Exception:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed < datetime.now(timezone.utc)


def _extract_same_origin_assets(html: str, base_url: str) -> list[str]:
    """Same-origin script/stylesheet URLs from the base page, order-preserving."""
    if BeautifulSoup is None or not html:
        return []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # pragma: no cover - defensive
        return []

    base_host = urlparse(base_url).netloc.lower()
    urls: list[str] = []
    for element in soup.find_all("script"):
        src = element.get("src")
        if src:
            urls.append(src.strip())
    for element in soup.find_all("link"):
        rel = element.get("rel") or []
        if isinstance(rel, str):
            rel = [rel]
        if not any("stylesheet" in str(item).lower() for item in rel):
            continue
        href = element.get("href")
        if href:
            urls.append(href.strip())

    resolved: list[str] = []
    for url in urls:
        absolute = urljoin(base_url, url)
        if urlparse(absolute).netloc.lower() == base_host and absolute not in resolved:
            resolved.append(absolute)
    return resolved


def analyze(base_url: str, timeout: int = 5, max_paths: int = 24, fetch_source_maps: bool = True) -> dict:
    """Probe a web root for sensitive artefacts, verifying every 200's content.

    Returns ``findings`` (content-verified) separately from ``candidates``
    (HTTP 200 whose body could not be confirmed as the artefact), so a catch-all
    router that answers 200 with an HTML shell produces no findings. Never
    raises: transport problems land in ``errors`` alongside whatever partial
    data was collected.

    ``security_txt`` hygiene problems (absent file, ``Expires`` in the past)
    and the ``crossdomain.xml`` wildcard are emitted as findings too, since the
    exact return schema has no separate ``issues`` list.
    """
    errors: list[str] = []
    findings: list[dict] = []
    candidates: list[dict] = []
    source_maps: list[dict] = []

    base = (base_url or "").rstrip("/")
    responses: dict[str, tuple[int, str, bytes]] = {}

    paths = _PATHS[: max(0, max_paths)]
    checked = 0
    for path in paths:
        url = base + path
        checked += 1
        try:
            # follow_redirects=False: a 302 to a login page must not masquerade
            # as a 200 for the requested artefact.
            with httpx.Client(timeout=max(1, timeout), verify=False, follow_redirects=False) as client:
                response = client.get(url, headers={"User-Agent": _USER_AGENT})
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            errors.append(f"{path}: {type(exc).__name__}: {exc}")
            continue
        except Exception as exc:
            errors.append(f"{path}: {type(exc).__name__}: {exc}")
            continue
        responses[path] = (response.status_code, _text_of(response), _raw_of(response))

    directory_listing = False

    # -- verified artefact findings -----------------------------------------
    for path, (status, text, raw) in responses.items():
        if status != 200:
            continue
        if _looks_like_listing(text):
            directory_listing = True
        if path in _QUIET_PATHS or path in _SECURITY_TXT_PATHS or path == _CROSSDOMAIN_PATH:
            continue
        artifact = _ARTIFACTS.get(path)
        if artifact is None:
            continue
        kind, severity, verifier = artifact
        try:
            verified, detail = verifier(text, raw)
        except Exception as exc:  # pragma: no cover - verifiers are pure
            errors.append(f"{path}: verifier {type(exc).__name__}: {exc}")
            continue
        if verified:
            findings.append(
                {
                    "path": path,
                    "status": status,
                    "severity": severity,
                    "kind": kind,
                    "detail": detail,
                    "evidence": _evidence(text),
                }
            )
        else:
            candidates.append({"path": path, "status": status, "note": detail})

    # -- security.txt (RFC 9116) -------------------------------------------
    security_txt: dict = {"present": False, "fields": {}, "expired": False}
    security_definitive = True
    for path in _SECURITY_TXT_PATHS:
        if path not in responses:
            security_definitive = False
            continue
        status, text, raw = responses[path]
        if status != 200:
            continue
        if _is_html(text):
            candidates.append(
                {"path": path, "status": status, "note": "HTTP 200 but body is an HTML shell, not security.txt"}
            )
            continue
        fields = _parse_security_txt(text)
        if not _looks_like_security_txt(fields):
            candidates.append(
                {
                    "path": path,
                    "status": status,
                    "note": "HTTP 200 but no recognizable security.txt fields (Contact/Expires/Policy/...)",
                }
            )
            continue
        security_txt = {"present": True, "fields": fields, "expired": _is_expired(fields.get("Expires"))}
        break

    if security_txt["present"] and security_txt["expired"]:
        expires = security_txt["fields"].get("Expires")
        findings.append(
            {
                "path": "/.well-known/security.txt",
                "status": 200,
                "severity": "low",
                "kind": "security_txt",
                "detail": f"security.txt Expires date is in the past ({expires})",
                "evidence": _evidence(str(expires)),
            }
        )
    elif not security_txt["present"] and security_definitive:
        findings.append(
            {
                "path": "/.well-known/security.txt",
                "status": 404,
                "severity": "info",
                "kind": "security_txt",
                "detail": "no security.txt published at /.well-known/security.txt or /security.txt",
                "evidence": "",
            }
        )

    # -- crossdomain.xml ----------------------------------------------------
    crossdomain: dict = {"present": False, "wildcard": False}
    if _CROSSDOMAIN_PATH in responses:
        status, text, raw = responses[_CROSSDOMAIN_PATH]
        if status == 200:
            if _DET is None:
                errors.append("/crossdomain.xml: defusedxml unavailable, XML not parsed")
            else:
                try:
                    root = _DET.fromstring(raw)
                    root_tag = root.tag.split("}")[-1].lower() if isinstance(root.tag, str) else ""
                    if root_tag != "cross-domain-policy":
                        # A well-formed HTML shell can parse as XML; only the
                        # real cross-domain-policy root proves this is the file.
                        raise ValueError(f"unexpected root element <{root_tag}>")
                    crossdomain["present"] = True
                    wildcard = False
                    for element in root.iter():
                        tag = element.tag.split("}")[-1].lower() if isinstance(element.tag, str) else ""
                        if tag == "allow-access-from" and (element.get("domain") or "").strip() == "*":
                            wildcard = True
                    crossdomain["wildcard"] = wildcard
                    if wildcard:
                        findings.append(
                            {
                                "path": _CROSSDOMAIN_PATH,
                                "status": status,
                                "severity": "medium",
                                "kind": "crossdomain_policy",
                                "detail": "crossdomain.xml allows access from any domain (<allow-access-from domain=\"*\"/>)",
                                "evidence": _evidence(text),
                            }
                        )
                except Exception as exc:
                    candidates.append(
                        {
                            "path": _CROSSDOMAIN_PATH,
                            "status": status,
                            "note": f"HTTP 200 but body is not parseable XML ({type(exc).__name__})",
                        }
                    )

    # -- base page: directory listing + source maps -------------------------
    page_html = ""
    try:
        with httpx.Client(timeout=max(1, timeout), verify=False, follow_redirects=True) as client:
            page = client.get(base + "/", headers={"User-Agent": _USER_AGENT})
        if page.status_code == 200:
            page_html = _text_of(page)
            if _looks_like_listing(page_html):
                directory_listing = True
    except Exception as exc:
        errors.append(f"{base}/: {type(exc).__name__}: {exc}")

    if fetch_source_maps:
        if BeautifulSoup is None:
            errors.append("source maps: beautifulsoup4 unavailable, base page not parsed")
        else:
            for asset in _extract_same_origin_assets(page_html, base)[:_SOURCE_MAP_LIMIT]:
                map_url = asset.split("?")[0].split("#")[0] + ".map"
                try:
                    with httpx.Client(timeout=max(1, timeout), verify=False, follow_redirects=False) as client:
                        map_response = client.get(map_url, headers={"User-Agent": _USER_AGENT})
                except Exception as exc:
                    errors.append(f"{map_url}: {type(exc).__name__}: {exc}")
                    continue
                if map_response.status_code != 200:
                    continue
                map_text = _text_of(map_response)
                try:
                    parsed_map = json.loads(map_text)
                except Exception:
                    continue
                if not isinstance(parsed_map, dict) or "version" not in parsed_map:
                    continue
                sources = parsed_map.get("sources") or []
                source_maps.append(
                    {
                        "url": map_url,
                        "status": map_response.status_code,
                        "size": len(_raw_of(map_response)),
                        "sources": len(sources) if isinstance(sources, list) else 0,
                    }
                )
                findings.append(
                    {
                        "path": urlparse(map_url).path,
                        "status": 200,
                        "severity": "low",
                        "kind": "source_map",
                        "detail": (
                            "published JavaScript source map exposes original source "
                            f"({len(sources) if isinstance(sources, list) else 0} sources)"
                        ),
                        "evidence": map_url,
                    }
                )

    return {
        "base_url": base_url,
        "findings": findings,
        "candidates": candidates,
        "directory_listing": directory_listing,
        "security_txt": security_txt,
        "crossdomain": crossdomain,
        "source_maps": source_maps,
        "checked": checked,
        "errors": errors,
    }
