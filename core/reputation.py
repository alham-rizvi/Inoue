# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
IP reputation and exposure signals from keyless public sources.

Two questions come up constantly when triaging an address that showed up in
a scan: *is this host known-bad?* and *what is exposed on it?* Both can be
answered without an account, without a key, and without touching the host
itself, which makes them safe to run early and cheap to run often.

The first source is Shodan's InternetDB, a free endpoint that returns the
ports, hostnames, CPEs, tags and known vulnerability identifiers Shodan has
already observed for an address. It is a summary of somebody else's
internet-wide scan, so it tells you what was visible *to Shodan* at some
point - not what is open right now, and not what is exploitable. A 404 from
it is a normal answer meaning "no information", and is reported as such
rather than as an error.

The second source is the DNS blocklists, queried directly over DNS. A
listing is a claim by a third party about past behaviour, and the lists
differ enormously in age and quality: SORBS in particular is widely
considered stale, and shared hosting, CGNAT and cloud egress ranges are
routinely listed because a *neighbour* misbehaved. A listing is therefore
worth mentioning and never worth escalating on its own. There is also a
sharper trap here: Spamhaus answers `127.255.255.x` when it is refusing a
query - typically because the request arrived through a public resolver it
does not serve - and that is a refusal, not a listing. Treating it as a
listing would produce a false positive on a large fraction of the
internet, so this module separates genuine `127.0.0.0/8` answers from the
refusal range and reports the latter as `refused`.

Nothing here is proof of maliciousness, and nothing here contacts the
target. Every lookup goes to a third party. Where a query fails, the result
is recorded as unknown: a DNS timeout is not a clean bill of health, and
`lookup_failed` exists precisely so that silence is never mistaken for a
negative finding.
"""

from __future__ import annotations

import ipaddress
import json
import re

_SHODAN_URL = "https://internetdb.shodan.io/{ip}"

# IPv4 blocklists queried directly. Each is free and keyless.
_IP_DNSBL_ZONES = (
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
)

# Domain-based blocklists, used only when the caller supplies a domain.
_DOMAIN_DNSBL_ZONES = (
    "dbl.spamhaus.org",
    "multi.surbl.org",
)

_ZONE_REASON = {
    "zen.spamhaus.org": "Spamhaus ZEN (combined SBL/XBL/PBL) listing",
    "bl.spamcop.net": "SpamCop blocklist listing (reported by spam traps)",
    "b.barracudacentral.org": "Barracuda Reputation Block List listing",
    "dnsbl.sorbs.net": "SORBS aggregate listing (legacy list, frequently stale)",
    "dbl.spamhaus.org": "Spamhaus DBL domain listing",
    "multi.surbl.org": "SURBL URI-reputation listing",
}

# Spamhaus ZEN encodes the sublist in the last octet of a 127.0.0.x answer.
_ZEN_SUBLIST = {
    2: "SBL",
    3: "SBL CSS",
    4: "XBL",
    5: "XBL",
    6: "XBL",
    7: "XBL",
    9: "SBL DROP",
    10: "PBL ISP",
    11: "PBL",
}

# Any answer inside 127.255.255.0/24 is Spamhaus signalling "query refused"
# (open resolver / excessive queries), NOT a listing.
_REFUSAL_NET = ipaddress.ip_network("127.255.255.0/24")
_RESPONSE_NET = ipaddress.ip_network("127.0.0.0/8")

# Shodan tags that carry enough signal to be worth surfacing in `issues`.
_HIGH_SIGNAL_TAGS = frozenset(
    {"tor", "proxy", "vpn", "compromised", "honeypot", "eol-os", "self-signed"}
)

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_](-?[A-Za-z0-9_])*\.)+[A-Za-z]{2,}$")


def _json_or_none(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def _http_get_json(url: str, timeout: int) -> tuple[int | None, object, str | None]:
    """GET a URL and parse JSON. Returns ``(status, payload, error)``.

    httpx is preferred; requests is a fallback for environments where only
    one of the two is installed. Failures are returned, never raised, so
    the caller can distinguish "no data" from "could not ask".
    """
    try:
        import httpx
    except Exception:
        httpx = None
    if httpx is not None:
        try:
            response = httpx.get(url, timeout=timeout, follow_redirects=True)
            return response.status_code, _json_or_none(response.text), None
        except Exception as exc:
            return None, None, f"{type(exc).__name__}: {exc}"
    try:
        import requests
        response = requests.get(url, timeout=timeout)
        return response.status_code, _json_or_none(response.text), None
    except Exception as exc:
        return None, None, f"{type(exc).__name__}: {exc}"


def _shodan_internetdb(ip: str, timeout: int) -> tuple[dict, bool, list[str]]:
    """Query Shodan InternetDB. Returns ``(payload, completed, errors)``.

    HTTP 404 is a documented, normal answer meaning "no information for
    this IP" - it is reported as ``available: False`` and deliberately kept
    out of ``errors``, because a clean answer is not a failure. Any other
    non-200, or a transport error, means the lookup did not complete.
    """
    payload = {
        "available": False,
        "ports": [],
        "hostnames": [],
        "cpes": [],
        "vulns": [],
        "tags": [],
        "error": None,
    }
    errors: list[str] = []
    status, body, error = _http_get_json(_SHODAN_URL.format(ip=ip), timeout)

    if status == 404:
        return payload, True, errors

    if status == 200 and isinstance(body, dict):
        payload["available"] = True
        for key in ("ports", "hostnames", "cpes", "vulns", "tags"):
            value = body.get(key)
            payload[key] = value if isinstance(value, list) else []
        return payload, True, errors

    if status is None:
        payload["error"] = error or "request failed"
        errors.append(
            f"Shodan InternetDB request for {ip} failed ({payload['error']}); exposure is "
            "unknown, not clean."
        )
    else:
        payload["error"] = f"HTTP {status}"
        errors.append(
            f"Shodan InternetDB returned HTTP {status} for {ip}; exposure is unknown, not clean."
        )
    return payload, False, errors


def _a_records(name: str, timeout: int) -> tuple[list[str], bool]:
    """Return ``(addresses, completed)`` for an A query.

    NXDOMAIN and NoAnswer mean the resolver answered and the name does not
    exist - for a blocklist that is a genuine "not listed". Timeouts and
    resolver errors mean we learned nothing and must not be read as clean.
    """
    try:
        import dns.resolver
    except Exception:
        return [], False
    try:
        answers = dns.resolver.resolve(name, "A", lifetime=timeout)
        return [str(record) for record in answers], True
    except Exception as exc:
        try:
            import dns.resolver as _resolver
            if isinstance(exc, (_resolver.NXDOMAIN, _resolver.NoAnswer)):
                return [], True
        except Exception:
            pass
        return [], False


def _classify_response(response: str) -> str:
    """Classify a blocklist answer: ``refused``, ``listed`` or ``unexpected``."""
    try:
        addr = ipaddress.ip_address(response)
    except Exception:
        return "unexpected"
    try:
        if addr in _REFUSAL_NET:
            return "refused"
        if addr in _RESPONSE_NET:
            return "listed"
    except Exception:
        return "unexpected"
    return "unexpected"


def _zone_reason(zone: str, response: str) -> str:
    """Human-readable reason, with the Spamhaus sublist decoded when known."""
    reason = _ZONE_REASON.get(zone, "DNS blocklist listing")
    if zone.endswith("spamhaus.org"):
        try:
            last = int(str(response).rsplit(".", 1)[-1])
        except Exception:
            last = None
        if last in _ZEN_SUBLIST:
            return f"{reason} - 127.0.0.{last} indicates {_ZEN_SUBLIST[last]}"
    return reason


def _check_zones(query_name: str, zones, timeout: int, dnsbl: dict, errors: list[str]) -> None:
    """Query blocklist zones for one query name, mutating ``dnsbl`` in place.

    A zone that answers with the refusal range is recorded under ``refused``
    and deliberately *not* under ``checked`` - it was not really checked. A
    zone whose lookup did not complete is recorded in ``errors`` and is not
    treated as clean.
    """
    for zone in zones:
        addresses, completed = _a_records(f"{query_name}.{zone}", timeout)
        if not completed:
            errors.append(
                f"DNSBL lookup {zone} did not complete (DNS timeout or resolver error); "
                "the result for this list is unknown, not clean."
            )
            continue
        refused_here = False
        for response in addresses:
            verdict = _classify_response(response)
            if verdict == "refused":
                refused_here = True
                if zone not in dnsbl["refused"]:
                    dnsbl["refused"].append(zone)
                continue
            if verdict == "listed":
                dnsbl["listed"].append(
                    {"zone": zone, "reason": _zone_reason(zone, response), "response": response}
                )
                continue
            errors.append(
                f"{zone} returned an unexpected answer ({response!r}); it was not treated "
                "as a listing."
            )
        if not refused_here:
            dnsbl["checked"].append(zone)


def _pydnsbl_extra(ip: str, timeout: int, dnsbl: dict) -> None:
    """Optional extra blocklist source via pydnsbl, if it happens to be installed.

    This is an enhancement only. The import is guarded, the provider set is
    capped and excludes zones already queried above, and every failure is
    swallowed - the optional dependency must never change the verdict of the
    built-in checks or raise into the caller.
    """
    try:
        import pydnsbl
    except Exception:
        return
    try:
        from pydnsbl.providers import BASE_PROVIDERS
    except Exception:
        BASE_PROVIDERS = []

    try:
        known = set(dnsbl.get("checked") or []) | set(dnsbl.get("refused") or [])
        extra = [
            provider
            for provider in BASE_PROVIDERS
            if getattr(provider, "host", "")
            and getattr(provider, "host", "") not in known
            and getattr(provider, "host", "") not in _IP_DNSBL_ZONES
        ][:3]
        if not extra:
            return
        checker = pydnsbl.DNSBLIpChecker(
            providers=extra, timeout=max(2, min(timeout, 5)), tries=1, concurrency=10
        )
        report = checker.check(ip)
    except Exception:
        return

    try:
        if not getattr(report, "blacklisted", False):
            return
        detected = getattr(report, "detected_by", None)
        if isinstance(detected, dict):
            zones = [str(key) for key in detected]
        elif isinstance(detected, (list, tuple, set)):
            zones = [str(item) for item in detected]
        else:
            zones = [getattr(provider, "host", "") for provider in extra]
        for zone in zones:
            zone = zone.strip()
            if not zone:
                continue
            if zone not in dnsbl["checked"]:
                dnsbl["checked"].append(zone)
            dnsbl["listed"].append(
                {
                    "zone": zone,
                    "reason": "pydnsbl reported a listing (optional cross-check)",
                    "response": "",
                }
            )
    except Exception:
        return


def _analyze_into(out: dict, ip: str, domain: str | None, timeout: int) -> None:
    """Do the work, mutating ``out``. Kept separate so ``analyze`` can guard it."""
    text = (ip or "").strip() if isinstance(ip, str) else ""
    try:
        addr = ipaddress.ip_address(text)
    except Exception:
        out["errors"].append(
            f"{ip!r} is not a valid IPv4 or IPv6 address - no reputation lookup was performed."
        )
        out["lookup_failed"] = True
        return

    per_query_timeout = max(2, min(timeout, 5))

    shodan, shodan_completed, shodan_errors = _shodan_internetdb(text, timeout)
    out["shodan_internetdb"] = shodan
    out["errors"].extend(shodan_errors)

    if addr.version == 4:
        reversed_ip = ".".join(reversed(text.split(".")))
        _check_zones(reversed_ip, _IP_DNSBL_ZONES, per_query_timeout, out["dnsbl"], out["errors"])
        _pydnsbl_extra(text, timeout, out["dnsbl"])
    else:
        out["dnsbl"]["note"] = (
            "IP blocklists are IPv4-only; the blocklist check was skipped for this IPv6 address."
        )

    if domain:
        name = domain.strip().lower()
        if _HOSTNAME_RE.match(name):
            _check_zones(name, _DOMAIN_DNSBL_ZONES, per_query_timeout, out["dnsbl"], out["errors"])
        else:
            out["errors"].append(
                f"{domain!r} is not a usable domain name; the domain-based blocklists were "
                "not checked."
            )

    dnsbl_completed = bool(out["dnsbl"]["checked"] or out["dnsbl"]["refused"])
    out["lookup_failed"] = not (shodan_completed or dnsbl_completed)

    for entry in out["dnsbl"]["listed"]:
        out["issues"].append(f"{entry['zone']}: {entry['reason']} (response {entry['response']}).")

    if shodan.get("available"):
        vulns = [str(item) for item in (shodan.get("vulns") or [])]
        if vulns:
            shown = ", ".join(vulns[:10]) + ("..." if len(vulns) > 10 else "")
            out["issues"].append(
                f"Shodan InternetDB associates {len(vulns)} known vulnerability identifier(s) "
                f"with {text} ({shown}). These come from third-party internet-wide scans and are "
                "not a validated, exploitable finding."
            )
        notable = [
            str(tag) for tag in (shodan.get("tags") or []) if str(tag).lower() in _HIGH_SIGNAL_TAGS
        ]
        if notable:
            out["issues"].append(
                f"Shodan InternetDB tags this address as {', '.join(notable)}; such tags are "
                "heuristics derived from scan behaviour and can be wrong."
            )


def analyze(ip: str, domain: str | None = None, timeout: int = 6) -> dict:
    """Check an IP against keyless reputation sources.

    ``domain`` is optional and only widens the blocklist check to the
    domain-based zones (Spamhaus DBL, SURBL) for that name; it is not
    required for the IP checks.

    Returns a plain dict and never raises: any unexpected failure is
    reported in ``errors`` with whatever partial data was gathered, and
    ``lookup_failed`` is set only when no source could be reached - never
    because a source answered "nothing found".
    """
    out = {
        "ip": ip,
        "shodan_internetdb": {
            "available": False,
            "ports": [],
            "hostnames": [],
            "cpes": [],
            "vulns": [],
            "tags": [],
            "error": None,
        },
        "dnsbl": {"listed": [], "checked": [], "refused": [], "note": None},
        "issues": [],
        "lookup_failed": False,
        "errors": [],
    }
    try:
        _analyze_into(out, ip, domain, timeout)
    except Exception as exc:
        out["errors"].append(
            f"unexpected error while checking {ip!r} ({type(exc).__name__}: {exc}); results are partial."
        )
        out["lookup_failed"] = True
    return out
