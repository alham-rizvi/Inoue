# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
HTTP posture checks derived from the response Inoue already fetched.

Four cheap, passive analyses that add real signal without extra requests
(except the optional OPTIONS probe, which is a single read-only call):

  * cookie security flags  - Secure / HttpOnly / SameSite
  * CSP weakness parsing   - unsafe-inline, unsafe-eval, wildcard sources
  * redirect chain         - protocol downgrades and cross-host hops
  * allowed HTTP methods   - via a single OPTIONS request

All of these report what the server *published*. None of them attempt to
exploit anything: no method is actually invoked beyond OPTIONS, no cookie
is replayed, no CSP bypass is attempted.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit

import httpx

# Methods that are worth flagging if a server advertises them.
_RISKY_METHODS = {
    "PUT": "Allows uploading/replacing resources if not access-controlled.",
    "DELETE": "Allows removing resources if not access-controlled.",
    "TRACE": "Can enable Cross-Site Tracing (XST); almost never needed.",
    "TRACK": "IIS equivalent of TRACE; almost never needed.",
    "CONNECT": "Can allow the server to be used as a proxy.",
    "PATCH": "Allows partial modification of resources if not access-controlled.",
}


def audit_cookies(set_cookie_headers: list[str]) -> list[dict]:
    """Check each Set-Cookie for the three standard protective attributes.

    Note the deliberate asymmetry: a missing `Secure` or `SameSite` is
    always worth flagging, but a missing `HttpOnly` is only a finding for
    cookies that look session-bearing - plenty of cookies (UI preferences,
    consent banners, analytics IDs) are *intentionally* readable by
    JavaScript, and flagging every one produces noise that buries the
    real ones.
    """
    findings = []
    for raw in set_cookie_headers or []:
        name = raw.split("=", 1)[0].strip()
        lowered = raw.lower()
        missing = []
        if "secure" not in lowered:
            missing.append("Secure")
        if "samesite" not in lowered:
            missing.append("SameSite")

        session_like = bool(re.search(r"sess|auth|token|login|sid|jwt|csrf", name, re.IGNORECASE))
        if session_like and "httponly" not in lowered:
            missing.append("HttpOnly")

        if missing:
            findings.append({
                "cookie": name,
                "missing": missing,
                "session_like": session_like,
                "detail": f"Set-Cookie '{name}' missing: {', '.join(missing)}",
            })
    return findings


def analyze_csp(csp_value: str) -> dict:
    """Parse a Content-Security-Policy and flag the directives that
    materially weaken it."""
    if not csp_value or not csp_value.strip():
        return {"present": False, "weaknesses": [], "directives": 0}

    weaknesses = []
    lowered = csp_value.lower()

    if "unsafe-inline" in lowered:
        weaknesses.append({
            "issue": "'unsafe-inline' allowed",
            "detail": "Inline scripts/styles are permitted, which removes most of CSP's XSS protection.",
        })
    if "unsafe-eval" in lowered:
        weaknesses.append({
            "issue": "'unsafe-eval' allowed",
            "detail": "eval() and equivalents are permitted, enabling a common XSS sink.",
        })

    # A wildcard in a fetch directive that controls code execution matters
    # far more than one in, say, img-src.
    for directive in ("script-src", "default-src", "object-src", "frame-src"):
        match = re.search(rf"{directive}\s+([^;]+)", lowered)
        if match and re.search(r"(^|\s)\*(\s|$)", match.group(1)):
            weaknesses.append({
                "issue": f"wildcard in {directive}",
                "detail": f"{directive} allows any origin, so the directive provides little restriction.",
            })

    if "default-src" not in lowered and "script-src" not in lowered:
        weaknesses.append({
            "issue": "no default-src or script-src",
            "detail": "Without either directive, script loading is effectively unrestricted.",
        })
    if "object-src" not in lowered and "default-src" not in lowered:
        weaknesses.append({
            "issue": "no object-src restriction",
            "detail": "Plugin content (<object>/<embed>) is unrestricted.",
        })

    directives = len([d for d in csp_value.split(";") if d.strip()])
    return {"present": True, "weaknesses": weaknesses, "directives": directives}


def analyze_redirect_chain(history, final_url: str) -> dict:
    """Inspect the redirect chain for protocol downgrades and host changes.

    `history` is httpx's response.history list.
    """
    hops = []
    downgrade = False
    cross_host = False

    previous = None
    for response in list(history or []) + []:
        url = str(response.url)
        hops.append({"url": url, "status": response.status_code})
        if previous:
            prev_parts, cur_parts = urlsplit(previous), urlsplit(url)
            if prev_parts.scheme == "https" and cur_parts.scheme == "http":
                downgrade = True
            if prev_parts.netloc and cur_parts.netloc and prev_parts.netloc != cur_parts.netloc:
                cross_host = True
        previous = url

    if previous and final_url:
        prev_parts, cur_parts = urlsplit(previous), urlsplit(final_url)
        if prev_parts.scheme == "https" and cur_parts.scheme == "http":
            downgrade = True
        if prev_parts.netloc and cur_parts.netloc and prev_parts.netloc != cur_parts.netloc:
            cross_host = True

    issues = []
    if downgrade:
        issues.append("Redirect chain downgrades from HTTPS to HTTP, exposing the request to interception.")
    if cross_host:
        issues.append("Redirect chain crosses to a different host - verify the destination is intended.")

    return {"hops": hops, "hop_count": len(hops), "https_downgrade": downgrade,
            "cross_host": cross_host, "issues": issues}


def check_http_methods(url: str, timeout: int = 6) -> dict:
    """Ask the server which methods it allows, via a single OPTIONS request.

    This only reads the advertised `Allow`/`Access-Control-Allow-Methods`
    header - it never actually issues PUT, DELETE, or anything else. An
    advertised method is not proof it's usable or unprotected.
    """
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            response = client.options(url, headers={"User-Agent": "Mozilla/5.0"})
    except Exception:
        return {"checked": False, "allowed": [], "risky": []}

    allow = response.headers.get("allow") or response.headers.get("access-control-allow-methods") or ""
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    risky = [
        {"method": m, "why": _RISKY_METHODS[m]}
        for m in methods if m in _RISKY_METHODS
    ]
    return {
        "checked": True,
        "status_code": response.status_code,
        "allowed": methods,
        "risky": risky,
        "note": "Advertised via OPTIONS only - not proof the method is usable or unprotected.",
    }


def analyze(headers: dict, final_url: str, history=None, check_methods: bool = False, timeout: int = 6) -> dict:
    """Run the full HTTP posture pass over an already-fetched response."""
    lowered = {k.lower(): v for k, v in (headers or {}).items()}

    # httpx lowercases and joins duplicate headers; split them back apart so
    # each Set-Cookie is audited individually rather than as one blob.
    raw_cookies = lowered.get("set-cookie", "")
    cookie_headers = [c for c in re.split(r",(?=[^;]+?=)", raw_cookies) if c.strip()] if raw_cookies else []

    result = {
        "cookies": audit_cookies(cookie_headers),
        "csp": analyze_csp(lowered.get("content-security-policy", "")),
        "redirects": analyze_redirect_chain(history, final_url),
    }
    if check_methods:
        result["http_methods"] = check_http_methods(final_url, timeout=timeout)
    return result
