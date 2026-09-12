"""Read-only JavaScript and response intelligence helpers."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlparse

import httpx

_SCRIPT_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.I)
_ENDPOINT_RE = re.compile(r"(?P<quote>['\"])(?P<path>(?:https?://[^'\"]+|/[^'\"\s]{2,}))(?P=quote)")
_FETCH_RE = re.compile(r"(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['\"]([^'\"]+)", re.I)
_HOST_RE = re.compile(r"\b(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b", re.I)
_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{1,63})=|\b(?:params|query|searchParams)\s*[:.]\s*([A-Za-z_][A-Za-z0-9_.-]{1,63})", re.I)
_SECRET_RE = re.compile(r"\b(?:AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,}|gh[pousr]_[A-Za-z0-9_]{16,}|xox[baprs]-[A-Za-z0-9-]{16,})\b")
_SENSITIVE_PATHS = ("/.env", "/.git/HEAD", "/.git/config", "/.DS_Store", "/docker-compose.yml", "/.aws/credentials", "/backup.zip", "/config.bak", "/index.php~")
_API_PATHS = ("/swagger.json", "/openapi.json", "/api-docs", "/.well-known/", "/graphql")


def script_sources(html: str, base_url: str) -> list[str]:
    seen = set(); result = []
    for raw in _SCRIPT_RE.findall(html or ""):
        absolute = urljoin(base_url, raw)
        if urlparse(absolute).scheme in {"http", "https"} and absolute not in seen:
            seen.add(absolute); result.append(absolute)
    return result


def redact_secret(value: str) -> str:
    return value if len(value) <= 8 else f"{value[:4]}…{value[-4:]}"


def parse_bundle(text: str, source_url: str = "") -> dict:
    endpoints = sorted(set(m.group(2) for m in _ENDPOINT_RE.finditer(text or "") if len(m.group(2)) < 500))
    fetch_calls = sorted(set(_FETCH_RE.findall(text or "")))
    hosts = sorted({re.sub(r"^https?://", "", value).split("/", 1)[0] for value in _HOST_RE.findall(text or "")})
    params = sorted({(a or b) for a, b in _PARAM_RE.findall(text or "") if a or b})
    secrets = [{"type": "pattern-matched-secret", "value": redact_secret(m.group(0)), "source": source_url} for m in _SECRET_RE.finditer(text or "")]
    maps = sorted(set(re.findall(r"//[#@]\s*sourceMappingURL=([^\s]+)", text or "")))
    return {"endpoints": endpoints, "fetch_calls": fetch_calls, "hosts": hosts, "parameters": params, "secrets": secrets, "source_maps": maps}


def collect_js_intel(base_url: str, html: str, timeout: int = 5, max_bundles: int = 20, client: httpx.Client | None = None) -> dict:
    sources = script_sources(html, base_url)[:max_bundles]
    own_client = client is None
    session = client or httpx.Client(timeout=timeout, verify=False, follow_redirects=True)
    bundles = []
    aggregate = {"endpoints": set(), "fetch_calls": set(), "hosts": set(), "parameters": set(), "secrets": [], "source_maps": set()}
    try:
        for source in sources:
            try:
                response = session.get(source, headers={"User-Agent": "Inoue/1.0 read-only recon"})
                if response.status_code >= 400 or "text" not in response.headers.get("content-type", "text/javascript"):
                    continue
                parsed = parse_bundle(response.text, source)
                bundles.append({"url": source, "sha256": hashlib.sha256(response.content).hexdigest(), "findings": parsed})
                for key in ("endpoints", "fetch_calls", "hosts", "parameters", "source_maps"):
                    aggregate[key].update(parsed[key])
                aggregate["secrets"].extend(parsed["secrets"])
            except Exception:
                continue
    finally:
        if own_client: session.close()
    return {"scripts": sources, "bundles": bundles, "endpoints": sorted(aggregate["endpoints"]), "fetch_calls": sorted(aggregate["fetch_calls"]), "hosts": sorted(aggregate["hosts"]), "parameters": sorted(aggregate["parameters"]), "secrets": aggregate["secrets"], "source_maps": sorted(aggregate["source_maps"])}


def grade_security_headers(headers: dict) -> dict:
    values = {str(k).lower(): str(v) for k, v in headers.items()}
    expected = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy")
    missing = [key for key in expected if key not in values]
    cors = {"wildcard_origin": values.get("access-control-allow-origin") == "*", "credentials_with_wildcard": values.get("access-control-allow-origin") == "*" and values.get("access-control-allow-credentials", "").lower() == "true"}
    return {"present": [key for key in expected if key in values], "missing": missing, "grade": "A" if not missing else "B" if len(missing) <= 1 else "C" if len(missing) <= 3 else "D", "cors": cors}


def conventional_paths(base_url: str) -> list[str]:
    return [urljoin(base_url, path) for path in _API_PATHS]


def exposure_paths(base_url: str) -> list[str]:
    return [urljoin(base_url, path) for path in _SENSITIVE_PATHS]
