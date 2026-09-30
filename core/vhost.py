# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Virtual-host (Host-header) discovery.

A single IP frequently fronts many names - a "default" site plus an admin
console, a staging copy, an internal tool, a CI server - and the extra names
are often reachable simply by asking for them. Because these names are not in
public DNS, they never show up in subdomain enumeration, so the Host header is
the only way in. It is a cheap, non-destructive check: one GET per candidate
name, nothing written, nothing brute-forced beyond a short fixed list.

The whole check hinges on one discipline, and the false-positive rule is the
point of the module: a server that answers *every* Host header with the same
200 page is a catch-all, and reporting each of those names as a "vhost" is the
classic way to generate twenty fake findings. A candidate is therefore only
reported as `found` when its response differs *meaningfully* from the baseline
we recorded for the IP itself - a different status code, a different `<title>`,
or a body length more than ~5% away from the baseline while being non-trivial.
An identical status and an identical body is a catch-all and is never reported.

Two further limits worth stating: the requests go to `{scheme}://{ip}/` with a
swapped Host header, so a name that only answers on a specific path or that is
served by a different IP in the same cluster will be missed; and "differs" here
means "differs from today's baseline", not "is a security problem". A distinct
response is a lead to go and look at, not a vulnerability.
"""

from __future__ import annotations

import re

import httpx

# A fixed, ordinary browser User-Agent, matching the rest of Inoue.
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"

# Short, high-signal list of names that commonly sit behind a shared IP. Kept
# deliberately small: each one costs a request and the aim is triage, not a
# full dictionary sweep.
_DEFAULT_CANDIDATES = [
    "admin", "dev", "staging", "test", "internal", "api", "portal", "vpn",
    "mail", "intranet", "jenkins", "gitlab", "jira", "wiki", "cdn", "static",
    "assets", "app", "beta", "uat",
]

# A body length difference smaller than this fraction of the baseline is treated
# as noise (dynamic banners, timestamps, request IDs).
_LENGTH_TOLERANCE = 0.05

# Below this many bytes a body is considered too small for a length difference
# to be meaningful.
_MIN_INTERESTING_LENGTH = 32


def _title(body: str) -> str:
    """Extract a `<title>` value, if any, from an HTML body."""
    if not body:
        return ""
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] if match else ""


def _probe(client: httpx.Client, url: str, host_header: str, timeout: int) -> dict | None:
    """Fetch `url` with an explicit Host header and summarise the response."""
    try:
        response = client.get(
            url,
            headers={"User-Agent": _USER_AGENT, "Host": host_header},
            timeout=max(1, timeout),
        )
    except Exception:
        return None
    body = response.text or ""
    return {"status": response.status_code, "length": len(body), "title": _title(body)}


def _differs(baseline: dict | None, candidate: dict | None) -> bool:
    """Decide whether a candidate response is meaningfully different.

    Requiring a real difference is what keeps a catch-all server from being
    reported as twenty virtual hosts.
    """
    if candidate is None or baseline is None:
        return False
    if candidate["status"] != baseline["status"]:
        return True
    if candidate["title"] != baseline["title"] and (candidate["title"] or baseline["title"]):
        return True
    base_len, cand_len = baseline["length"], candidate["length"]
    largest = max(base_len, cand_len)
    if largest >= _MIN_INTERESTING_LENGTH and abs(cand_len - base_len) / max(largest, 1) > _LENGTH_TOLERANCE:
        return True
    return False


def discover(
    ip: str,
    hostname: str,
    wordlist: list[str] | None = None,
    timeout: int = 5,
    max_candidates: int = 20,
    scheme: str = "http",
) -> dict:
    """Discover virtual hosts reachable on `ip` by varying the Host header.

    `scheme` is only the scheme to try *first*: if the baseline request does not
    answer, it is retried once over the other scheme and whichever answered is
    used for every candidate, so an HTTPS-only target is still reachable without
    doubling the request count. Then one request per candidate name (as
    `<name>.<hostname>`, and again as bare `<name>`), up to `max_candidates`
    distinct names. `scheme` in the result reports which scheme actually worked.
    Never raises: transport failures are collected in `errors`.
    """
    requested = (scheme or "").strip().lower()
    if requested not in ("http", "https"):
        requested = "http"
    # The scheme to try first, then the other one as a fallback. Detecting the
    # scheme from the baseline keeps this bounded: at most two baseline
    # requests, never two per candidate.
    schemes_to_try = [requested] + [other for other in ("https", "http") if other != requested]

    result: dict = {
        "ip": ip,
        "hostname": hostname,
        "scheme": requested,
        "baseline": {"status": None, "length": 0, "title": ""},
        "candidates_checked": 0,
        "found": [],
        "issues": [],
        "errors": [],
    }

    # Build the bounded, de-duplicated candidate list (defaults first, then any
    # caller-supplied names), then hard-cap it.
    names: list[str] = []
    for name in list(_DEFAULT_CANDIDATES) + list(wordlist or []):
        if name and name not in names:
            names.append(name)
    if max_candidates > 0:
        names = names[:max_candidates]

    try:
        client = httpx.Client(timeout=max(1, timeout), verify=False, follow_redirects=True)
    except Exception as exc:
        result["errors"].append(f"could not create HTTP client: {exc}")
        return result

    with client:
        # Baseline: the IP asked for by name. No explicit Host override, which
        # also covers `Host: <ip>` since that is what httpx sends by default.
        # The scheme is settled here and then reused for every candidate.
        baseline = None
        for candidate_scheme in schemes_to_try:
            baseline = _probe(client, f"{candidate_scheme}://{ip}/", ip, timeout)
            if baseline is not None:
                result["scheme"] = candidate_scheme
                break
        if baseline is None:
            tried = " or ".join(f"{candidate}://{ip}/" for candidate in schemes_to_try)
            result["errors"].append(f"baseline request to {tried} failed")
        else:
            result["baseline"] = baseline

        base_url = f"{result['scheme']}://{ip}/"

        for name in names:
            for host_header in (f"{name}.{hostname}", name):
                result["candidates_checked"] += 1
                candidate = _probe(client, base_url, host_header, timeout)
                if candidate is None:
                    result["errors"].append(f"request with Host: {host_header} failed")
                    continue
                if _differs(result["baseline"] if result["baseline"]["status"] is not None else None, candidate):
                    result["found"].append({
                        "host": host_header,
                        "status": candidate["status"],
                        "length": candidate["length"],
                        "title": candidate["title"],
                        "distinct": True,
                    })

    if result["baseline"]["status"] is None:
        result["issues"].append(
            "No usable baseline response from the IP over "
            f"{' or '.join(schemes_to_try)} - virtual-host comparison is "
            "unreliable and any result should be treated as provisional."
        )
    elif not result["found"]:
        result["issues"].append(
            "No candidate differed from the baseline; the server appears to answer "
            "every Host header identically (catch-all), so no virtual hosts are reported."
        )

    return result
