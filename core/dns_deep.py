# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
DNS depth beyond the usual A/MX/NS/TXT lookups.

The records here quietly decide how much authority a domain hands out,
and every one of them is public DNS - so the cost is a handful of queries
and zero requests to the target:

* **CAA** - which certificate authorities are even permitted to issue for
  this domain. With no CAA record, *any* CA can be talked into issuing a
  certificate for it, so the record is the difference between "mis-issuance
  requires compromising this domain's DNS" and "mis-issuance requires
  compromising any CA".
* **SRV** - service discovery that frequently leaks internal hostnames and
  infrastructure (SIP, LDAP, Kerberos, autodiscover) that never shows up in
  a web crawl.
* **DNSSEC** - whether the zone is signed at all. Without it, any answer on
  the path can be spoofed; with it, the resolver can prove it was not.
* **AXFR** - a zone transfer is the whole zone in one answer. Every
  nameserver that is not an authorised secondary is supposed to refuse it.
  When one does not, the entire namespace - including hosts that were never
  meant to be public - is disclosed in a single request.
* **Wildcard DNS** - if ``*.domain`` resolves, then "this subdomain exists"
  stops being evidence of anything, which changes how every other subdomain
  finding in a report should be read.

Two correctness rules are enforced throughout:

1. A lookup that *failed* (timeout, resolver error) is never reported as a
   record being *absent*. ``NXDOMAIN``/``NoAnswer`` mean the record is
   genuinely not published; a timeout means we do not know, and the
   presence flag is reported as ``None`` rather than ``False``.
2. A refused AXFR is the normal, healthy outcome and is not an error. Only
   a transfer that actually succeeds is surfaced - and loudly.

Everything is best-effort and passive: nothing here modifies DNS, claims a
resource, or brute-forces anything.
"""

from __future__ import annotations

import secrets

# Conventional service locations. A short fixed list keeps the lookup cost
# bounded; an empty result only means none of *these* names exist, not that
# the domain runs no services at all.
_SRV_NAMES = [
    "_sip._tcp",
    "_sip._udp",
    "_xmpp-server._tcp",
    "_xmpp-client._tcp",
    "_imap._tcp",
    "_submission._tcp",
    "_autodiscover._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_caldavs._tcp",
    "_carddavs._tcp",
]

# A refused transfer is the expected answer. These rcodes all mean "no" and
# must never be reported as an error.
_AXFR_REFUSAL_RCODES = ("REFUSED", "NOTAUTH", "SERVFAIL", "NOTIMP", "FORMERR")


def _query(host: str, rtype: str, timeout: int) -> tuple[list, str]:
    """Return ``(answers, status)`` for one lookup.

    ``status`` is one of:

    * ``"ok"``     - the lookup completed and returned at least one record.
    * ``"absent"`` - the lookup completed and the record genuinely does not
      exist (``NXDOMAIN`` or ``NoAnswer``).
    * ``"failed"`` - the lookup did not complete (timeout, resolver or
      network error). Absence is *not* established in this case.

    This never raises: distinguishing "resolved, no such record" from
    "lookup failed" matters, because reporting a DNS timeout as "record
    missing" is a confidently wrong security claim.
    """
    try:
        import dns.resolver

        return list(dns.resolver.resolve(host, rtype, lifetime=timeout)), "ok"
    except Exception as exc:  # noqa: BLE001 - a lookup must never propagate
        try:
            import dns.resolver

            if isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
                return [], "absent"
        except Exception:
            pass
        return [], "failed"


def _registrable_parent(domain: str) -> str | None:
    """Best-effort registrable domain (``www.a.example.co.uk`` -> ``example.co.uk``).

    Uses tldextract's *bundled* public-suffix snapshot (``suffix_list_urls=()``)
    so this stays offline; falls back to naive label trimming if it is
    unavailable.
    """
    try:
        import tldextract

        extract = tldextract.TLDExtract(suffix_list_urls=())
        parts = extract(domain)
        if parts.domain and parts.suffix:
            return f"{parts.domain}.{parts.suffix}"
    except Exception:
        pass
    labels = domain.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) > 2 else None


def _caa(domain: str, timeout: int) -> tuple[list[dict], bool | None, list[str]]:
    """CAA records, checked at the domain and then at its registrable parent.

    CAA is normally published at the apex, so a query against a subdomain can
    legitimately come back empty while the parent has a policy - the parent
    lookup avoids reporting "no CAA" for a domain that does have one.

    ``caa_present`` is tri-state: ``True``/``False`` when the lookup
    completed, ``None`` when it did not (see the module docstring).
    """
    errors: list[str] = []
    candidates = [domain]
    parent = _registrable_parent(domain)
    if parent and parent != domain:
        candidates.append(parent)

    for host in candidates:
        answers, status = _query(host, "CAA", timeout)
        if status == "ok":
            return [_caa_record(r) for r in answers], True, errors
        if status == "failed":
            errors.append(
                f"CAA lookup for {host} did not complete (DNS timeout or resolver error) - absence is NOT established."
            )
            return [], None, errors
    return [], False, errors


def _caa_record(rdata) -> dict:
    """Normalise one CAA rdata into ``{flags, tag, value}`` (bytes -> text)."""

    def _as_text(value) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", "replace")
        return str(value)

    return {
        "flags": int(getattr(rdata, "flags", 0) or 0),
        "tag": _as_text(getattr(rdata, "tag", "")),
        "value": _as_text(getattr(rdata, "value", "")),
    }


def _srv(domain: str, timeout: int, errors: list[str]) -> dict:
    """Probe the conventional SRV names; return only those that answer."""
    found: dict[str, list[dict]] = {}
    for prefix in _SRV_NAMES:
        fqdn = f"{prefix}.{domain}"
        answers, status = _query(fqdn, "SRV", timeout)
        if status == "failed":
            errors.append(
                f"SRV lookup for {fqdn} did not complete (DNS timeout or resolver error) - absence is NOT established."
            )
            continue
        if status != "ok":
            continue
        found[fqdn] = [
            {
                "priority": int(getattr(r, "priority", 0) or 0),
                "weight": int(getattr(r, "weight", 0) or 0),
                "port": int(getattr(r, "port", 0) or 0),
                "target": str(getattr(r, "target", "")).rstrip("."),
            }
            for r in answers
        ]
    return found


def _dnssec(domain: str, timeout: int, errors: list[str]) -> tuple[list[str], int, bool | None]:
    """DS at the domain/parent and DNSKEY at the zone.

    ``dnssec_signed`` is tri-state, exactly like ``caa_present``: ``True`` when
    DNSSEC material was found, ``False`` only when every lookup *completed* and
    found nothing, and ``None`` when a lookup did not complete (see the module
    docstring). A signed zone publishes a DNSKEY and its parent carries a DS
    that chains it to the root, so any positive answer settles the question;
    only a clean empty answer may be reported as "not signed", because a
    timeout reported as "not signed" would be a confidently wrong security
    claim. Absence of DNSSEC is not itself a misconfiguration - it is a recon
    data point.
    """
    ds_answers, ds_status = _query(domain, "DS", timeout)
    if ds_status == "failed":
        errors.append(
            f"DS lookup for {domain} did not complete (DNS timeout or resolver error) - DNSSEC status is NOT established."
        )

    dnskey_answers, dnskey_status = _query(domain, "DNSKEY", timeout)
    if dnskey_status == "failed":
        errors.append(
            f"DNSKEY lookup for {domain} did not complete (DNS timeout or resolver error) - DNSSEC status is NOT established."
        )

    ds_records = [str(r).strip() for r in ds_answers]
    dnskey_count = len(dnskey_answers)

    signed: bool | None
    if dnskey_count > 0 or bool(ds_records):
        signed = True
    elif ds_status == "failed" or dnskey_status == "failed":
        # At least one lookup did not complete and neither produced material,
        # so nothing is established: the flag stays unknown rather than
        # asserting "not signed".
        signed = None
    else:
        signed = False
    return ds_records, dnskey_count, signed


def _nameservers(domain: str, timeout: int, errors: list[str]) -> list[dict]:
    """Resolve each NS to its A/AAAA addresses.

    The addresses are what an AXFR attempt actually has to connect to, and
    they often reveal the real hosting provider behind a CDN-fronted name.
    """
    answers, status = _query(domain, "NS", timeout)
    if status == "failed":
        errors.append(
            f"NS lookup for {domain} did not complete (DNS timeout or resolver error) - nameservers are NOT established."
        )
        return []

    nameservers: list[dict] = []
    for rdata in answers:
        host = str(getattr(rdata, "target", rdata)).rstrip(".").lower()
        if not host:
            continue
        ips: list[str] = []
        for rtype in ("A", "AAAA"):
            ip_answers, ip_status = _query(host, rtype, timeout)
            if ip_status == "failed":
                errors.append(
                    f"{rtype} lookup for nameserver {host} did not complete (DNS timeout or resolver error)."
                )
            else:
                ips.extend(str(ip).strip() for ip in ip_answers)
        nameservers.append({"host": host, "ips": ips})
    return nameservers


def _is_axfr_refusal(exc: Exception) -> bool:
    """True when an exception is a server-side refusal rather than a failure."""
    text = f"{type(exc).__name__}: {exc}".upper()
    if any(code in text for code in _AXFR_REFUSAL_RCODES):
        return True
    try:
        import dns.query
        import dns.rcode

        if isinstance(exc, dns.query.TransferError):
            return dns.rcode.to_text(exc.rcode()).upper() in _AXFR_REFUSAL_RCODES
    except Exception:
        pass
    return False


def _axfr(domain: str, nameservers: list[dict], timeout: int, errors: list[str]) -> dict:
    """Attempt a zone transfer against each nameserver.

    A refusal is the expected, healthy result and is deliberately *not*
    recorded as an error. Only a transfer that completes is reported as
    ``allowed``.
    """
    result = {
        "attempted": False,
        "allowed": False,
        "records": 0,
        "nameservers_tried": [],
        "errors": [],
    }
    if not nameservers:
        return result

    xfr_timeout = min(2, timeout) if timeout and timeout > 0 else 2
    try:
        import dns.query
        import dns.zone
    except Exception as exc:  # pragma: no cover - dnspython is a hard dependency
        result["errors"].append(f"dnspython AXFR support unavailable: {exc}")
        return result

    for ns in nameservers:
        host = ns.get("host") or ""
        target = (ns.get("ips") or [host])[0]
        if not target:
            continue
        result["attempted"] = True
        result["nameservers_tried"].append(host)

        try:
            transfer = dns.query.xfr(target, domain, timeout=xfr_timeout)
            zone = dns.zone.from_xfr(transfer)
        except Exception as exc:  # noqa: BLE001 - refusals are normal
            if _is_axfr_refusal(exc):
                continue
            message = f"AXFR to {host or target} did not complete: {type(exc).__name__}: {exc}"
            result["errors"].append(message)
            errors.append(message)
            continue

        records = 0
        try:
            for _name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    records += len(rdataset)
        except Exception:
            records = len(getattr(zone, "nodes", {}))

        result["allowed"] = True
        result["records"] = records
        return result

    return result


def _wildcard(domain: str, timeout: int, errors: list[str]) -> dict:
    """Detect wildcard DNS with two independent random labels.

    A wildcard makes every ``*.domain`` name resolve, so two random labels
    resolving is strong evidence. A single resolution is accepted only when
    the second probe could not complete - we would rather over-report a
    wildcard than silently miss one, because it changes how every other
    subdomain finding should be read.
    """
    resolved = 0
    completed = 0
    answers: list[str] = []
    for _ in range(2):
        label = f"inoue-wildcard-{secrets.token_hex(4)}.{domain}"
        records, status = _query(label, "A", timeout)
        if status == "failed":
            errors.append(
                f"Wildcard probe for {label} did not complete (DNS timeout or resolver error) - detection is inconclusive."
            )
            continue
        completed += 1
        if status == "ok":
            resolved += 1
            answers.extend(str(r).strip() for r in records)

    detected = resolved >= 2 or (resolved >= 1 and completed < 2)
    return {"detected": detected, "answers": sorted(set(answers))}


def analyze(domain: str, timeout: int = 5) -> dict:
    """Full DNS-depth posture for a domain.

    Returns a dict with the keys ``domain``, ``caa``, ``caa_present``,
    ``srv``, ``ds``, ``dnskey_count``, ``dnssec_signed``, ``ns``, ``axfr``,
    ``wildcard``, ``issues`` and ``errors``.

    ``caa_present`` is tri-state (``None`` means the lookup did not
    complete). ``errors`` collects only genuine lookup failures - a refused
    AXFR is not an error.
    """
    issues: list[str] = []
    errors: list[str] = []
    domain = (domain or "").strip().rstrip(".").lower()

    caa, caa_present, caa_errors = _caa(domain, timeout)
    errors.extend(caa_errors)
    srv = _srv(domain, timeout, errors)
    ds, dnskey_count, dnssec_signed = _dnssec(domain, timeout, errors)
    nameservers = _nameservers(domain, timeout, errors)
    axfr = _axfr(domain, nameservers, timeout, errors)
    wildcard = _wildcard(domain, timeout, errors)

    if caa_present is False:
        issues.append(
            "No CAA record published - any certificate authority may issue certificates for this domain."
        )
    if axfr["allowed"]:
        issues.append(
            "Zone transfer (AXFR) ALLOWED by "
            f"{', '.join(axfr['nameservers_tried'])} - the full DNS zone "
            f"({axfr['records']} records) was disclosed. Restrict transfers to authorised secondaries."
        )
    if wildcard["detected"]:
        issues.append(
            "Wildcard DNS detected - a random label resolves, so any subdomain 'exists'. "
            "Subdomain enumeration results must be verified by content, not by resolution."
        )

    return {
        "domain": domain,
        "caa": caa,
        "caa_present": caa_present,
        "srv": srv,
        "ds": ds,
        "dnskey_count": dnskey_count,
        "dnssec_signed": dnssec_signed,
        "ns": nameservers,
        "axfr": axfr,
        "wildcard": wildcard,
        "issues": issues,
        "errors": errors,
    }
