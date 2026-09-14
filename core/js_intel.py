# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
JS bundle harvesting and analysis.

Two problems this closes:

1. **SPA detection gap.** Every one of the ~20,000 entries in
   `fingerprints/signatures.py` matches against the initial HTML response
   - but a client-rendered app (Next.js/Nuxt/Vue/React SPA) ships almost
   no real content in that initial HTML; everything lives in the JS
   bundle. Rather than inventing a whole new signature schema, this
   module fetches the bundles and feeds their text back through the
   *existing* fingerprint engine as extra HTML-token corpus - so all
   20,000 signatures get a real shot at matching against what a browser
   would actually render, for free.

2. **Recon value.** JS bundles routinely leak API endpoint paths, and
   sometimes hardcoded credentials that should never have shipped
   client-side. We surface both, but never write a full secret to disk
   or console - only a redacted form (first/last 4 characters) with the
   pattern that matched, enough to confirm a real finding without this
   tool itself becoming a secret-leaking liability.

Nothing here executes JavaScript. It's still static analysis - regex and
JSON parsing over the bundle text - just applied to more of the page than
before.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

import httpx

MAX_BUNDLES = 5
MAX_BUNDLE_BYTES = 500_000  # ~500KB per bundle is plenty of signal; most are far smaller

_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

_ENDPOINT_RE = re.compile(
    r'''["'`](/(?:api|graphql|v[0-9]+|rest)[a-zA-Z0-9_/\-]{0,80})["'`]''',
)

_HYDRATION_MARKERS = {
    "window.__NEXT_DATA__": "Next.js",
    "window.__NUXT__": "Nuxt.js",
    "window.__INITIAL_STATE__": "SSR initial state (generic)",
    "window.__APOLLO_STATE__": "Apollo GraphQL",
    "window.__PRELOADED_STATE__": "Redux preloaded state (generic)",
    "window.__REMIX_CONTEXT__": "Remix",
}

# (label, pattern, min_length) - patterns look for the *shape* of a secret,
# not any specific real-world key, and every match is redacted before it
# ever leaves this module.
_SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 20),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 39),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b"), 20),
    ("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), 28),
    ("Generic Bearer Token Assignment", re.compile(r'''(?:token|secret|api_?key)["']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{24,})["\']''', re.IGNORECASE), 24),
]


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def collect_script_urls(body: str, base_url: str, limit: int = MAX_BUNDLES) -> list[str]:
    """External script URLs from the page, in document order, biased
    toward likely app bundles over third-party libraries.

    Deliberately NOT restricted to the page's exact origin: plenty of
    sites serve their own first-party JS from a dedicated asset domain
    (e.g. github.com's scripts all come from github.githubassets.com -
    a completely different registrable domain, by design, to sandbox
    cookies). An origin filter would silently exclude exactly the
    bundles most worth fetching. Instead, when there are more candidates
    than `limit`, prefer ones whose path looks like an app bundle
    (main/app/bundle/chunk/_next/static) over ones that look like a
    well-known third-party tracker.
    """
    if not body:
        return []
    urls: list[str] = []
    seen: set[str] = set()
    for src in _SCRIPT_SRC_RE.findall(body):
        absolute = urljoin(base_url, src)
        if absolute in seen:
            continue
        seen.add(absolute)
        urls.append(absolute)

    if len(urls) <= limit:
        return urls

    bundle_hint = re.compile(r"(main|app|bundle|chunk|_next|index|static)", re.IGNORECASE)
    third_party_hint = re.compile(
        r"(google-analytics|googletagmanager|gtag|facebook\.net|hotjar|segment\.(io|com)|mixpanel|doubleclick)",
        re.IGNORECASE,
    )
    preferred = [u for u in urls if bundle_hint.search(u) and not third_party_hint.search(u)]
    rest = [u for u in urls if u not in preferred]
    return (preferred + rest)[:limit]


def fetch_js_bundles(urls: list[str], timeout: int = 10) -> dict[str, str]:
    """Fetch each URL, capped per-bundle so one huge vendor bundle can't
    blow the scan's time/memory budget."""
    bundles: dict[str, str] = {}
    for url in urls:
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                response = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code == 200 and response.text:
                bundles[url] = response.text[:MAX_BUNDLE_BYTES]
        except Exception:
            continue
    return bundles


def extract_hydration_payloads(body: str) -> list[dict]:
    """Detect SSR/hydration state markers directly in the initial HTML -
    no bundle fetch needed, and often enough on its own to identify the
    framework even before any JS runs."""
    if not body:
        return []
    findings = []
    for marker, framework in _HYDRATION_MARKERS.items():
        if marker in body:
            findings.append({"marker": marker, "framework": framework})
    return findings


def extract_endpoints(bundles: dict[str, str], limit: int = 50) -> list[str]:
    """Candidate API endpoint paths referenced in JS bundles. This is a
    recon signal for later parameter/endpoint fuzzing with a dedicated
    tool - Inoue surfaces the list, it doesn't probe any of them."""
    found: set[str] = set()
    for content in bundles.values():
        for match in _ENDPOINT_RE.findall(content):
            found.add(match)
            if len(found) >= limit:
                return sorted(found)
    return sorted(found)


def detect_secret_patterns(bundles: dict[str, str]) -> list[dict]:
    """Pattern-match likely leaked credentials in JS bundles. Every match
    is redacted before being returned - callers never see the full value,
    only enough to confirm and locate the finding."""
    findings = []
    seen_redacted: set[str] = set()
    for url, content in bundles.items():
        for label, pattern, min_len in _SECRET_PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(1) if match.groups() else match.group(0)
                if len(value) < min_len:
                    continue
                redacted = _redact(value)
                dedup_key = f"{label}:{redacted}"
                if dedup_key in seen_redacted:
                    continue
                seen_redacted.add(dedup_key)
                findings.append({"type": label, "redacted": redacted, "source": url})
    return findings


def harvest(body: str, base_url: str, timeout: int = 10, max_bundles: int = MAX_BUNDLES) -> dict:
    """Run the full JS intel pass: hydration payloads from the HTML,
    then fetch a bounded set of same-origin scripts and mine them for
    endpoints and redacted secret patterns."""
    hydration = extract_hydration_payloads(body)
    script_urls = collect_script_urls(body, base_url, limit=max_bundles)
    bundles = fetch_js_bundles(script_urls, timeout=timeout)
    endpoints = extract_endpoints(bundles)
    secrets = detect_secret_patterns(bundles)

    return {
        "hydration_payloads": hydration,
        "scripts_fetched": list(bundles.keys()),
        "scripts_attempted": script_urls,
        "endpoints": endpoints,
        "secret_findings": secrets,
        "bundle_text": bundles,  # kept for the caller to re-run fingerprinting against; not serialized as-is
    }


# Backward-compatible helpers retained for integrations from the previous API.
_LEGACY_FETCH_RE = re.compile(r"(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['\"]([^'\"]+)", re.I)
_LEGACY_HOST_RE = re.compile(r"\b(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?\b", re.I)
_LEGACY_SECRET_RE = re.compile(r"\b(?:AKIA[0-9A-Z]{12,}|AIza[0-9A-Za-z_-]{20,}|gh[pousr]_[A-Za-z0-9_]{16,}|xox[baprs]-[A-Za-z0-9-]{16,})\b")
def script_sources(html: str, base_url: str) -> list[str]:
    return collect_script_urls(html, base_url, limit=MAX_BUNDLES)
def parse_bundle(text: str, source_url: str = "") -> dict:
    text = text or ""
    endpoints = extract_endpoints({source_url: text})
    fetch_calls = sorted(set(_LEGACY_FETCH_RE.findall(text)))
    hosts = sorted({re.sub(r"^https?://", "", value).split("/", 1)[0] for value in _LEGACY_HOST_RE.findall(text)})
    params = sorted(set(re.findall(r"[?&]([A-Za-z_][A-Za-z0-9_.-]{1,63})=", text)))
    secrets = [{"type": "pattern-matched-secret", "value": _redact(m.group(0)), "source": source_url} for m in _LEGACY_SECRET_RE.finditer(text)]
    return {"endpoints": endpoints, "fetch_calls": fetch_calls, "hosts": hosts, "parameters": params, "secrets": secrets, "source_maps": sorted(set(re.findall(r"//[#@]\s*sourceMappingURL=([^\s]+)", text)))}
def grade_security_headers(headers: dict) -> dict:
    values = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    expected = ("strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy")
    missing = [key for key in expected if not values.get(key)]
    cors = {"wildcard_origin": values.get("access-control-allow-origin") == "*", "credentials_with_wildcard": values.get("access-control-allow-origin") == "*" and values.get("access-control-allow-credentials", "").lower() == "true"}
    return {"present": [key for key in expected if values.get(key)], "missing": missing, "grade": "A" if not missing else "B" if len(missing) <= 1 else "C" if len(missing) <= 3 else "D", "cors": cors}
