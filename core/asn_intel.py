# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Routing and ownership context for an IP address, from public DNS.

Which autonomous system announces an address - and which prefix it belongs
to - is quiet, high-value recon. It tells you whether a target sits on a
residential eyeball network, a hosting provider, or a cloud range, and that
changes how any later finding should be read: an SSRF that reaches a cloud
provider's range is a different story from one that stays inside a tenant
VPC, and "the WAF blocked us" means more on an edge network than on a
single-tenant rack. It also gives a defensible answer to the first question
in almost every report - *who is this address, actually?*

All of it comes from Team Cymru's public DNS service, which needs no
account, no key, and sends nothing to the target itself. That convenience
is also the reason for a firm caveat: what comes back is what the *global
routing table* says about the origin of an address, published on a
best-effort basis. It is not proof of who owns the machine, who operates
it, or that the address is in any way malicious. Large providers announce
blocks on behalf of thousands of customers, so "GOOGLE" in the AS name is a
statement about routing, not about the tenant running on that IP. Treat
every field here as context for a report, never as a standalone finding.

Two things this module deliberately does not do. It does not contact the
target: every query goes to a third-party resolver zone, so nothing is sent
to the host being investigated. And it does not guess. When a lookup fails,
the fields stay `None` and `lookup_failed` is set, because a DNS timeout is
not evidence that an address is unannounced - reporting a failed lookup as
"no ASN" would be a confidently wrong claim. A query that succeeds and has
no answer is a genuine absence and is reported as such, under `notes`.

The IPv6 path is best-effort. Team Cymru expects the nibble-reversed form
of the address under `origin6.asn.cymru.com`; that is what is built here,
but the service's IPv6 coverage is thinner than its IPv4 coverage, so an
empty answer for a v6 address is more likely to mean "not covered" than
"not announced".
"""

from __future__ import annotations

import ipaddress
import os

# Team Cymru DNS zones (free, keyless, no signup).
_SOURCE = "team-cymru"
_ORIGIN_ZONE = "origin.asn.cymru.com"
_ORIGIN6_ZONE = "origin6.asn.cymru.com"
_ASN_ZONE = "asn.cymru.com"

# Optional local ASN database for cross-checking. If none of these exist and
# the environment variable is unset, the cross-check is skipped silently -
# pyasn is an enhancement here, never a requirement.
_PYASN_DB_ENV = "INOUE_PYASN_DB"
_PYASN_DB_CANDIDATES = (
    "/usr/share/pyasn/ipasn.dat",
    "/usr/local/share/pyasn/ipasn.dat",
    "/var/lib/pyasn/ipasn.dat",
    "/opt/pyasn/ipasn.dat",
)


def _txt(hostname: str, timeout: int) -> tuple[list[str], bool]:
    """Return ``(records, lookup_completed)`` for a TXT query.

    The distinction between "completed, no record" and "did not complete"
    is the whole point. NXDOMAIN and NoAnswer mean the resolver answered:
    the record genuinely does not exist. A timeout, a refused query, or a
    dead resolver means we learned nothing, and callers must not turn that
    silence into a negative security statement.

    Import is attempted inside the function so that a missing dnspython
    degrades to "not completed" rather than an import-time crash.
    """
    try:
        import dns.resolver
    except Exception:
        return [], False
    try:
        answers = dns.resolver.resolve(hostname, "TXT", lifetime=timeout)
        return [str(record).strip('"').replace('" "', "") for record in answers], True
    except Exception as exc:
        try:
            import dns.resolver as _resolver
            if isinstance(exc, (_resolver.NXDOMAIN, _resolver.NoAnswer)):
                return [], True
        except Exception:
            pass
        return [], False


def _non_public_reason(addr) -> str | None:
    """Describe why an address is not globally routable, or ``None`` if it is.

    Registries do not announce these ranges, so querying them wastes a
    lookup and - worse - invites a confusing empty answer. Detecting them
    up front lets the caller say "this is a private address" plainly.
    """
    try:
        if addr.is_loopback:
            return "loopback range (127.0.0.0/8 or ::1)"
        if addr.is_link_local:
            return "link-local range (169.254.0.0/16 or fe80::/10)"
        if addr.is_multicast:
            return "multicast range"
        if addr.is_unspecified:
            return "unspecified address (0.0.0.0 or ::)"
        if addr.is_reserved:
            return "reserved range"
        if addr.is_private:
            return "private (RFC 1918 / non-globally-routable) range"
    except Exception:
        return None
    return None


def _origin_query(addr) -> str:
    """Build the Team Cymru origin query name for an address.

    IPv4 uses the reversed octet form (``1.1.1.1`` -> ``1.1.1.1.origin...``);
    IPv6 uses the reversed *nibble* form under ``origin6``. Building the v6
    name is best-effort: the query is well-formed, but the service's v6
    coverage is the limiting factor, not the name.
    """
    if addr.version == 4:
        return ".".join(reversed(str(addr).split("."))) + "." + _ORIGIN_ZONE
    nibbles = addr.exploded.replace(":", "").replace(".", "")
    return ".".join(reversed(nibbles)) + "." + _ORIGIN6_ZONE


def _fields(record: str) -> list[str]:
    """Split a Team Cymru pipe-separated record into trimmed fields."""
    return [field.strip() for field in record.split("|")]


def _pyasn_crosscheck(addr, asn: int | None, prefix: str | None) -> tuple[str | None, list[str]]:
    """Compare Team Cymru's answer against a local pyasn database, if present.

    Only runs when pyasn is importable *and* a database file can be found;
    otherwise it returns nothing at all, so the module never depends on it.
    Disagreement is reported as a note, not an error: routing data is a
    moving target and neither source is authoritative about the other.
    """
    database = os.environ.get(_PYASN_DB_ENV) or ""
    if not database or not os.path.exists(database):
        database = ""
        for candidate in _PYASN_DB_CANDIDATES:
            if os.path.exists(candidate):
                database = candidate
                break
    if not database:
        return None, []
    try:
        import pyasn
        local = pyasn.pyasn(database)
        local_asn, local_prefix = local.lookup(str(addr))
    except Exception:
        # Optional enrichment only - a broken local database must not
        # downgrade or fail the primary answer.
        return None, []
    if local_asn is None:
        return None, []
    if asn is not None:
        try:
            if int(local_asn) != int(asn):
                return (
                    f"local pyasn database disagrees: it maps {addr} to AS{local_asn} "
                    f"({local_prefix}) while Team Cymru reports AS{asn} ({prefix}); "
                    "routing data changes over time and neither source is authoritative.",
                    [],
                )
        except Exception:
            return None, []
    return f"local pyasn database agrees with Team Cymru (AS{local_asn}, {local_prefix}).", []


def analyze(ip: str, timeout: int = 5) -> dict:
    """Resolve the announcing AS, prefix and registry for an IP address.

    Returns a plain dict and never raises. Network and DNS work is wrapped
    so that any failure yields partial data plus an ``errors`` entry, and
    ``lookup_failed`` is set *only* when a query did not complete - never
    when a query completed and simply had no answer.
    """
    result = {
        "ip": ip,
        "asn": None,
        "prefix": None,
        "country": None,
        "registry": None,
        "allocated": None,
        "as_name": None,
        "source": None,
        "is_private": False,
        "lookup_failed": False,
        "notes": [],
        "errors": [],
    }

    text = (ip or "").strip() if isinstance(ip, str) else ""
    try:
        addr = ipaddress.ip_address(text)
    except Exception:
        result["errors"].append(
            f"{ip!r} is not a valid IPv4 or IPv6 address - no ASN lookup was attempted."
        )
        result["lookup_failed"] = True
        return result

    reason = _non_public_reason(addr)
    if reason is not None:
        result["is_private"] = True
        result["notes"].append(
            f"{text} is in a {reason}; no ASN lookup was performed, because these "
            "addresses are not announced in the global routing table."
        )
        return result

    result["source"] = _SOURCE
    records, completed = _txt(_origin_query(addr), timeout)
    if not completed:
        result["lookup_failed"] = True
        result["errors"].append(
            f"Team Cymru origin lookup for {text} did not complete (DNS timeout or "
            "resolver error) - the ASN is unknown, not absent."
        )
        return result

    if not records:
        result["notes"].append(
            f"Team Cymru returned no origin record for {text}; the address is not "
            "announced in the routing table it serves, or is outside its coverage."
        )
        return result

    fields = _fields(records[0])
    asn_token = fields[0] if fields else ""
    if asn_token:
        parts = asn_token.split()
        try:
            result["asn"] = int(parts[0])
        except Exception:
            result["notes"].append(
                f"Team Cymru returned an unparseable ASN field ({asn_token!r}); the "
                "remaining fields are still reported."
            )
        if len(parts) > 1:
            result["notes"].append(
                f"multiple originating ASNs reported ({asn_token}); only the first is recorded."
            )
    if len(fields) > 1:
        result["prefix"] = fields[1] or None
    if len(fields) > 2:
        result["country"] = fields[2] or None
    if len(fields) > 3:
        result["registry"] = fields[3] or None
    if len(fields) > 4:
        result["allocated"] = fields[4] or None

    if result["asn"] is not None:
        name_records, name_completed = _txt(f"AS{result['asn']}.{_ASN_ZONE}", timeout)
        if not name_completed:
            result["notes"].append(
                "AS name lookup did not complete (DNS timeout or resolver error); the "
                "ASN and prefix above are still valid."
            )
        elif not name_records:
            result["notes"].append(f"no AS name is published for AS{result['asn']}.")
        else:
            name_fields = _fields(name_records[0])
            if len(name_fields) > 4 and name_fields[4]:
                result["as_name"] = name_fields[4]
            else:
                result["notes"].append(
                    f"AS name record for AS{result['asn']} was not in the expected form "
                    f"({name_records[0]!r}); it is not reported."
                )

    note, errors = _pyasn_crosscheck(addr, result["asn"], result["prefix"])
    if note:
        result["notes"].append(note)
    result["errors"].extend(errors)

    return result
