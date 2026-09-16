# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Subdomain takeover fingerprinting.

A takeover candidate is a subdomain whose DNS still points at a
third-party service (S3, GitHub Pages, Heroku, Azure...) where the
underlying resource no longer exists - meaning someone else could
potentially claim that resource and serve content from the victim's
hostname. It's one of the highest-signal, lowest-effort findings in bug
bounty work.

This module is strictly **detection only**: it issues a plain GET and
matches the response body against the well-known "this service exists
but this specific resource doesn't" error pages. It never attempts to
register, claim, or create anything on the third-party service - that
would be exploitation, not recon.

A match here is a *candidate*, not a confirmed vulnerability. Several of
these fingerprints (notably the S3 and Azure ones) can also appear on
domains that are perfectly healthy but temporarily misconfigured, so the
output says "candidate" and reports the matched fingerprint rather than
asserting an exploitable takeover.
"""

from __future__ import annotations

import re
from typing import Optional

import httpx

# (service, fingerprint pattern, cname hint or None, notes)
# Fingerprints are the documented, publicly known error strings each
# service returns for an unclaimed resource.
_TAKEOVER_FINGERPRINTS = [
    ("AWS S3", r"NoSuchBucket|The specified bucket does not exist", r"s3[.-]|amazonaws\.com",
     "Bucket referenced by DNS/CNAME no longer exists."),
    ("GitHub Pages", r"There isn't a GitHub Pages site here", r"github\.io",
     "GitHub Pages site not configured for this hostname."),
    ("Heroku", r"No such app|herokucdn\.com/error-pages/no-such-app", r"herokuapp\.com|herokudns\.com",
     "Heroku app no longer exists."),
    ("Shopify", r"Sorry, this shop is currently unavailable", r"myshopify\.com",
     "Shopify store unavailable or unclaimed."),
    ("Fastly", r"Fastly error: unknown domain", r"fastly", 
     "Domain not configured on the Fastly service."),
    ("Bitbucket", r"Repository not found", r"bitbucket\.io",
     "Bitbucket-hosted site not found."),
    ("Ghost", r"The thing you were looking for is no longer here", r"ghost\.io",
     "Ghost publication not found."),
    ("Surge.sh", r"project not found", r"surge\.sh",
     "Surge project not found."),
    ("Tumblr", r"Whatever you were looking for doesn't currently exist at this address",
     r"tumblr\.com", "Tumblr blog not found."),
    ("Unbounce", r"The requested URL was not found on this server", r"unbouncepages\.com",
     "Unbounce page not found."),
    ("Webflow", r"The page you are looking for doesn't exist or has been moved", r"proxy-ssl\.webflow\.com",
     "Webflow site not configured for this hostname."),
    ("Zendesk", r"Help Center Closed", r"zendesk\.com",
     "Zendesk Help Center closed or unclaimed."),
    ("Readthedocs", r"unknown to Read the Docs", r"readthedocs\.io",
     "Read the Docs project not found."),
    ("Pantheon", r"The gods are wise, but do not know of the site which you seek",
     r"pantheonsite\.io", "Pantheon site not found."),
    ("Netlify", r"Not Found - Request ID", r"netlify\.app|netlify\.com",
     "Netlify site not configured for this hostname."),
    ("Cargo Collective", r"404 Not Found", r"cargocollective\.com",
     "Cargo site not found (generic 404 - verify manually)."),
]

_COMPILED = [
    (service, re.compile(pattern, re.IGNORECASE), re.compile(cname, re.IGNORECASE) if cname else None, note)
    for service, pattern, cname, note in _TAKEOVER_FINGERPRINTS
]


def check_takeover(hostname: str, cname: Optional[str] = None, timeout: int = 8) -> Optional[dict]:
    """Fetch `hostname` and check the response against known unclaimed-resource
    fingerprints. Returns a candidate dict on a match, else None.

    `cname` (when known from DNS) raises confidence: a matching error body
    AND a CNAME pointing at that same service is far stronger evidence than
    the error body alone, which can appear on unrelated 404 pages.
    """
    url = hostname if hostname.startswith(("http://", "https://")) else f"https://{hostname}"
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            response = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        body = response.text[:100_000]
        status = response.status_code
    except Exception:
        return None

    for service, pattern, cname_pattern, note in _COMPILED:
        match = pattern.search(body)
        if not match:
            continue
        cname_matches = bool(cname and cname_pattern and cname_pattern.search(cname))
        # Generic fingerprints (a bare "404 Not Found") are far too common to
        # report on the body alone - require CNAME corroboration for those.
        generic = pattern.pattern in (r"404 Not Found", r"The requested URL was not found on this server")
        if generic and not cname_matches:
            continue
        return {
            "hostname": hostname,
            "service": service,
            "confidence": "high" if cname_matches else "medium",
            "status_code": status,
            "cname": cname,
            "matched_fingerprint": match.group(0)[:80],
            "note": note,
            "caveat": "Candidate only - verify manually. Inoue does not attempt to claim the resource.",
        }
    return None


def check_takeover_batch(hostnames: list[str], cnames: Optional[dict] = None, timeout: int = 8, max_hosts: int = 25) -> list[dict]:
    """Check a bounded list of subdomains for takeover candidates."""
    from concurrent.futures import ThreadPoolExecutor

    cnames = cnames or {}
    targets = [h for h in hostnames if h][:max_hosts]
    if not targets:
        return []

    def check(host: str):
        return check_takeover(host, cname=cnames.get(host), timeout=timeout)

    findings = []
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as executor:
        for result in executor.map(check, targets):
            if result:
                findings.append(result)
    return findings
