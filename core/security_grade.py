# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Security header grading and CORS misconfiguration detection.

Both are computed from headers Inoue already fetched during the normal
page request - no extra requests, always on, essentially free. The goal
is fast triage: "is this worth a closer look" across a large target list,
not a full security audit.
"""

from __future__ import annotations

import re

# (header name, why it matters) - presence is checked case-insensitively;
# for CSP and Permissions-Policy, an empty or clearly-too-permissive value
# is treated the same as "missing" since an empty policy provides no
# protection.
_EXPECTED_HEADERS = [
    ("strict-transport-security", "Forces HTTPS on future visits; without it, a user's first visit (or any downgrade attempt) can be intercepted."),
    ("content-security-policy", "Restricts what scripts/resources the page can load; the single strongest defense against XSS."),
    ("x-frame-options", "Prevents the page from being embedded in an iframe elsewhere (clickjacking)."),
    ("x-content-type-options", "Stops the browser from guessing content types, blocking some MIME-confusion attacks."),
    ("referrer-policy", "Controls how much of this page's URL leaks to external sites via the Referer header."),
    ("permissions-policy", "Restricts access to browser features (camera, geolocation, etc.) for embedded/third-party content."),
]


def grade_security_headers(headers: dict) -> dict:
    """Return which of the common protective headers are present/missing,
    plus a simple 0-100 score (not a substitute for a real audit - a fast
    triage signal for comparing many targets at a glance)."""
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    present = []
    missing = []
    for name, why in _EXPECTED_HEADERS:
        value = lowered.get(name)
        if value and value.strip():
            present.append(name)
        else:
            missing.append({"header": name, "why_it_matters": why})

    score = round(100 * len(present) / len(_EXPECTED_HEADERS))
    return {"present": present, "missing": missing, "score": score}


def detect_cors_misconfig(headers: dict) -> list[dict]:
    """Flag the two CORS patterns that are almost always a real problem:

    1. Wildcard origin + credentials allowed together. Per the CORS spec
       browsers should reject this combination outright, but plenty of
       real-world proxies/frameworks emit it anyway (or reflect the
       request's Origin verbatim rather than literally sending '*',
       which sidesteps the spec restriction and is functionally the
       same hole) - either shape lets any site read authenticated
       responses cross-origin.
    2. A reflected-Origin pattern with credentials allowed: the server
       echoes back whatever Origin the browser sent instead of validating
       it against an allowlist, which achieves the same effect as #1.

    A bare `Access-Control-Allow-Origin: *` with no credentials header is
    intentionally NOT flagged - that's the normal, safe way to serve a
    public API and flagging it would just be noise.
    """
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    origin = lowered.get("access-control-allow-origin", "")
    credentials = lowered.get("access-control-allow-credentials", "").strip().lower()

    if credentials != "true":
        return []

    findings = []
    if origin.strip() == "*":
        findings.append({
            "issue": "Wildcard origin with credentials allowed",
            "detail": "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true lets any site read authenticated responses cross-origin.",
            "evidence": f"Access-Control-Allow-Origin: {origin}",
        })
    elif origin and origin.strip() not in ("", "null"):
        # Can't tell from a single response alone whether this is a fixed
        # allowlisted value or a reflected Origin - but it's still worth
        # flagging as "verify this isn't a blanket reflection" rather than
        # silently passing it, since reflection is a very common mistake.
        findings.append({
            "issue": "Origin allowed with credentials - verify this isn't reflected",
            "detail": "A specific origin is allowed alongside credentials. If the server reflects whatever Origin it receives rather than checking against a real allowlist, this is equivalent to a wildcard.",
            "evidence": f"Access-Control-Allow-Origin: {origin}",
        })

    return findings
