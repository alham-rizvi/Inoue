# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Subresource Integrity (SRI) audit of an already-fetched HTML page.

Subresource Integrity is the `integrity` attribute on a `<script>` or
`<link rel="stylesheet">`: the browser refuses to execute or apply the resource
unless its bytes hash to the pinned value. It is the only thing standing between
a page and a compromised third-party CDN, and it is what turns "we load a script
from someone else's domain" into "we load *exactly this script* from someone
else's domain". The finding that carries real value is therefore a third-party
subresource with no `integrity` - the operator does not control that host, so
they cannot fix a compromise there after the fact. Same-origin resources without
SRI are reported only as informational.

This module needs no network access: it reads the page body the caller already
has and never fetches a subresource itself.

The false-positive limits matter here more than usual, and they are the reason
the score is scoped to external resources only:

  * SRI is only *checkable* by the browser for resources it can fetch in CORS
    mode - a same-origin or CORS-enabled resource. Absence of `integrity` on a
    first-party asset is not a vulnerability; the asset already rides in on the
    operator's own origin.
  * An HTML page may legitimately contain no external subresources at all. That
    is a perfect score (100), not a finding.
  * `integrity` without `crossorigin` is only meaningful for cross-origin
    resources; it is reported at low severity because on some setups the
    attribute is simply omitted and SRI still works via the asset's own CORS
    headers.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import tldextract
from bs4 import BeautifulSoup

# Schemes that carry their content inline; they are never fetched as a
# subresource, so SRI does not apply and they are skipped entirely.
_INLINE_SCHEMES = ("data:", "blob:", "javascript:", "about:")


def _is_external(url: str) -> bool:
    """True for absolute (scheme://...) or protocol-relative (//host/...) URLs."""
    if url.startswith("//"):
        return True
    return bool(re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.IGNORECASE))


def _host_of(url: str) -> str | None:
    """Return the host of an external URL, or None for a relative/inline URL."""
    if url.startswith("//"):
        return url[2:].split("/", 1)[0].split("?", 1)[0].lower() or None
    if re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.IGNORECASE):
        return (urlsplit(url).netloc or "").lower() or None
    return None


def _registrable(host: str) -> str:
    """Reduce a host to its registrable domain (e.g. a.b.example.co.uk -> example.co.uk)."""
    extracted = tldextract.extract(host)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return (host or "").lower()


def _severity_for(third_party: bool) -> str:
    # Third-party resources without SRI are the finding worth acting on; the
    # operator cannot vouch for a host they do not run.
    return "medium" if third_party else "low"


def audit(body: str, base_url: str = "", timeout: int = 5) -> dict:
    """Audit the SRI coverage of a page's scripts and stylesheets.

    Pure and offline: `body` is the HTML already fetched by the caller and no
    subresource is ever requested. `base_url` is only used to tell a third-party
    host from a first-party one. `timeout` is accepted for signature symmetry
    with the other recon modules and is intentionally unused. Never raises.
    """
    result: dict = {
        "scripts_total": 0,
        "scripts_external": 0,
        "scripts_missing_integrity": 0,
        "stylesheets_total": 0,
        "stylesheets_external": 0,
        "stylesheets_missing_integrity": 0,
        "crossorigin_missing": 0,
        "findings": [],
        "score": 100,
        "issues": [],
        "errors": [],
    }

    try:
        soup = BeautifulSoup(body or "", "html.parser")
    except Exception as exc:
        result["errors"].append(f"could not parse HTML: {exc}")
        return result

    base_host = (urlsplit(base_url).netloc or "").lower() if base_url else ""
    base_registrable = _registrable(base_host) if base_host else ""
    if base_url and not base_registrable:
        result["issues"].append(
            "base_url did not yield a registrable domain; third-party classification "
            "may be inaccurate."
        )
    if not base_url:
        result["issues"].append(
            "No base_url supplied, so all external subresources are treated as "
            "first-party and third-party findings will be under-reported."
        )

    # Collect (kind, url, tag) for every script[src] and stylesheet link[href].
    resources: list[tuple[str, str, object]] = []
    for tag in soup.find_all("script", src=True):
        resources.append(("script", tag.get("src", "").strip(), tag))
    for tag in soup.find_all("link"):
        rel = tag.get("rel") or []
        rel = rel if isinstance(rel, list) else [rel]
        if any(str(r).lower() == "stylesheet" for r in rel) and tag.get("href"):
            resources.append(("stylesheet", tag.get("href", "").strip(), tag))

    external_total = 0
    external_with_integrity = 0

    for kind, url, tag in resources:
        if not url:
            continue
        lowered_url = url.lower()
        if lowered_url.startswith(_INLINE_SCHEMES):
            continue

        is_script = kind == "script"
        if is_script:
            result["scripts_total"] += 1
        else:
            result["stylesheets_total"] += 1

        integrity = (tag.get("integrity") or "").strip()
        has_integrity = bool(integrity)
        if not has_integrity:
            if is_script:
                result["scripts_missing_integrity"] += 1
            else:
                result["stylesheets_missing_integrity"] += 1

        external = _is_external(url)
        if is_script:
            result["scripts_external"] += int(external)
        else:
            result["stylesheets_external"] += int(external)

        host = _host_of(url) if external else None
        if host and base_registrable:
            third_party = _registrable(host) != base_registrable
        else:
            third_party = False  # relative, or no base to compare against

        if external:
            external_total += 1
            if has_integrity:
                external_with_integrity += 1

        # --- findings ------------------------------------------------------
        if not has_integrity:
            result["findings"].append({
                "type": kind,
                "src": url,
                "third_party": third_party,
                "severity": _severity_for(third_party),
                "issue": (
                    f"{'Third-party' if third_party else 'Same-origin'} {kind} loaded "
                    "without Subresource Integrity"
                ),
                "detail": (
                    f"'{url}' is loaded without an integrity attribute, so the browser "
                    "will execute/apply whatever bytes that host returns. "
                    + (
                        "The host is outside the operator's control, so a compromise "
                        "there cannot be detected or pinned against."
                        if third_party
                        else "The resource is same-origin, so this is informational "
                        "rather than a direct exposure."
                    )
                ),
            })

        if has_integrity and not (tag.get("crossorigin") or "").strip():
            result["crossorigin_missing"] += 1
            result["findings"].append({
                "type": kind,
                "src": url,
                "third_party": third_party,
                "severity": "low",
                "issue": f"{kind} has integrity but no crossorigin attribute",
                "detail": (
                    f"'{url}' pins an integrity hash but omits crossorigin, so the "
                    "hash is only enforced on setups that also send the right CORS "
                    "headers; adding crossorigin=\"anonymous\" makes verification reliable."
                ),
            })

    # Score: 100 means every *external* subresource carries integrity. No
    # external subresources at all is a clean 100, not a missing-signal.
    result["score"] = round(100 * external_with_integrity / external_total) if external_total else 100

    return result
