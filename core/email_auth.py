# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Email-authentication depth: the records that sit *behind* SPF and DMARC.

``core.email_security`` answers "is SPF/DMARC published, and how strict is
the stated policy". This module answers the follow-up questions that decide
whether a domain actually *enforces* what it publishes, and whether the
supporting pieces are in place:

* **BIMI** - a logo plus a Verified Mark Certificate that providers only
  honour once DMARC is at enforcement. Its absence is not a weakness; its
  presence is a strong signal that the rest of the stack is mature.
* **TLS-RPT** - a reporting address so a domain finds out when mail to it is
  being delivered over an unauthenticated connection.
* **MTA-STS** - a policy published in *two* places: a DNS record
  (``v=STSv1``) and an HTTPS policy file. The DNS record without the policy
  file - or a policy stuck in ``testing``/``none`` - looks configured but
  enforces nothing, which is the classic half-finished deployment.
* **DKIM key material** - which selectors exist and how large the keys are.
  Small keys are brute-forceable, and a key published with an empty ``p=``
  is revoked: the selector is advertised but cannot verify anything.
* **DMARC detail** - the sub-policy tags (``sp``, ``aspf``, ``adkim``,
  ``pct``, ``fo``) that decide how much of the mailstream the top-level
  ``p=`` tag actually covers. ``p=reject`` with ``pct=10`` is a very
  different posture from ``p=reject`` with ``pct=100``.

Two correctness rules, the same ones ``core.email_security`` enforces:

1. A lookup that *failed* is never reported as a record being *absent*. The
   presence flags are tri-state (``True``/``False``/``None``), and ``None``
   means "unknown, the lookup did not complete" - never a confident claim
   that a security control is missing. The converse holds too: a lookup that
   *completed* and found no record means the record is genuinely absent, and is
   reported as ``present=False``.
2. DKIM selectors are arbitrary strings chosen by the domain, so "none of
   the selectors I guessed resolved" is *not* evidence that DKIM is
   unconfigured. The output says so explicitly.

No mail is sent and nothing is spoofed: this is public DNS plus one
unauthenticated HTTPS fetch of the policy file the domain already publishes.
"""

from __future__ import annotations

import base64
import binascii
import re

import httpx

# A deliberately broader fixed list than core.email_security's. Still only a
# guess - the authoritative list lives in the domain's own DNS, not here.
_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "k2",
    "mail",
    "dkim",
    "s1",
    "s2",
    "smtp",
    "mandrill",
    "mailjet",
    "sendgrid",
    "amazonses",
    "zoho",
    "protonmail",
    "cm",
    "mta",
    "sqs",
    "k3",
    "pm",
    "dk",
    "dk1",
    "dk2",
    "s1024",
    "s2048",
    "20230601",
    "20221208",
    "test",
]

# Keys shorter than this are weak enough to be worth flagging.
_WEAK_KEY_BITS = 1024


def _txt(host: str, timeout: int) -> tuple[list[str], str]:
    """Return ``(records, status)`` for a TXT lookup.

    ``status`` is ``"ok"`` (records returned), ``"absent"`` (the lookup
    completed and no such record exists) or ``"failed"`` (the lookup did not
    complete). Never raises.
    """
    try:
        import dns.resolver

        answers = list(dns.resolver.resolve(host, "TXT", lifetime=timeout))
    except Exception as exc:  # noqa: BLE001 - a lookup must never propagate
        try:
            import dns.resolver

            if isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
                return [], "absent"
        except Exception:
            pass
        return [], "failed"

    records: list[str] = []
    for rdata in answers:
        chunks = getattr(rdata, "strings", None)
        if chunks:
            text = "".join(
                part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
                for part in chunks
            )
        else:
            text = str(rdata)
        records.append(text.strip('"'))
    return records, "ok"


def _key_bits(value: str) -> int:
    """Approximate DKIM key size in bits from the base64 ``p=`` value.

    The ``p=`` tag is a base64-encoded SubjectPublicKeyInfo. The decoded DER
    byte length times 8 is a close approximation of the key size (the DER
    wrapper adds a small, roughly fixed overhead). An empty value means the
    key was revoked, and reports 0.
    """
    cleaned = re.sub(r"\s+", "", value or "")
    if not cleaned:
        return 0
    padding = "=" * (-len(cleaned) % 4)
    try:
        raw = base64.b64decode(cleaned + padding, validate=False)
    except (binascii.Error, ValueError):
        return 0
    return len(raw) * 8


def _tag_value(match) -> str | None:
    """Return a parsed ``tag=value`` value without its ``;`` separator.

    BIMI and TLS-RPT records are semicolon-separated, so a value that is
    followed by another tag is captured together with the separator
    (``l=https://host/logo.svg;``). The separator is record syntax, not part of
    the URL or address, so it is stripped here along with any padding.
    """
    if not match:
        return None
    return match.group(1).strip().rstrip(";").strip() or None


def _bimi(domain: str, timeout: int) -> dict:
    """Parse the BIMI record at ``_bimi.<domain>``.

    ``present`` is tri-state: ``None`` when the lookup did not complete,
    ``False`` when it completed and no BIMI record is published, ``True`` when
    one was found.
    """
    result = {"present": None, "record": None, "logo_url": None, "vmc_url": None}
    records, status = _txt(f"_bimi.{domain}", timeout)
    if status == "failed":
        # The lookup did not complete: presence is unknown, NOT absent.
        return result

    record = next((r for r in records if r.lower().startswith("v=bimi1")), None)
    if not record:
        # The lookup completed and no BIMI record is published: absent.
        result["present"] = False
        return result

    logo = re.search(r"\bl\s*=\s*(\S+)", record, re.IGNORECASE)
    vmc = re.search(r"\ba\s*=\s*(\S+)", record, re.IGNORECASE)
    return {
        "present": True,
        "record": record[:300],
        "logo_url": _tag_value(logo),
        "vmc_url": _tag_value(vmc),
    }


def _tls_rpt(domain: str, timeout: int) -> dict:
    """Parse the TLS-RPT record at ``_smtp._tls.<domain>``.

    ``present`` is tri-state, with the same meaning as in :func:`_bimi`.
    """
    result = {"present": None, "record": None, "rua": None}
    records, status = _txt(f"_smtp._tls.{domain}", timeout)
    if status == "failed":
        # The lookup did not complete: presence is unknown, NOT absent.
        return result

    record = next((r for r in records if "v=tlsrptv1" in r.lower()), None)
    if not record:
        # The lookup completed and no TLS-RPT record is published: absent.
        result["present"] = False
        return result

    rua = re.search(r"\brua\s*=\s*(\S+)", record, re.IGNORECASE)
    return {
        "present": True,
        "record": record[:300],
        "rua": _tag_value(rua),
    }


def _dkim(domain: str, timeout: int) -> tuple[dict, bool]:
    """Probe the extended DKIM selector list.

    Returns ``(result, lookup_failed)``. ``key_bits`` maps each found
    selector to the approximate key size in bits (0 = revoked key).
    """
    checked: list[str] = []
    found: list[str] = []
    key_bits: dict[str, int] = {}
    lookup_failed = False

    for selector in _DKIM_SELECTORS:
        checked.append(selector)
        records, status = _txt(f"{selector}._domainkey.{domain}", timeout)
        if status == "failed":
            lookup_failed = True
            continue
        if status != "ok":
            continue

        record = next(
            (
                r
                for r in records
                if "v=dkim1" in r.lower() or re.search(r"\bp\s*=", r, re.IGNORECASE)
            ),
            None,
        )
        if not record:
            continue

        found.append(selector)
        key = re.search(r"\bp\s*=\s*([A-Za-z0-9+/=]*)", record, re.IGNORECASE)
        if key is not None:
            key_bits[selector] = _key_bits(key.group(1))

    return {"selectors_checked": checked, "selectors_found": found, "key_bits": key_bits}, lookup_failed


def _mta_sts(domain: str, timeout: int) -> dict:
    """MTA-STS: the DNS record *and* the HTTPS policy file it points at."""
    result = {"dns_present": None, "policy_present": None, "mode": None, "max_age": None, "mx": []}
    records, status = _txt(f"_mta-sts.{domain}", timeout)
    if status == "failed":
        # dns_present stays None: we do not know whether the record exists.
        return result

    result["dns_present"] = any("v=stsv1" in r.lower() for r in records)
    if not result["dns_present"]:
        result["policy_present"] = False
        return result

    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            response = client.get(policy_url, headers={"User-Agent": "Mozilla/5.0"})
        if response.status_code != 200:
            result["policy_present"] = False
            return result

        fields: dict[str, str] = {}
        mx: list[str] = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "mx":
                mx.append(value.lower())
            elif key:
                fields[key] = value

        result["policy_present"] = bool(fields)
        result["mode"] = (fields.get("mode") or "").lower() or None
        if fields.get("max_age"):
            try:
                result["max_age"] = int(fields["max_age"])
            except ValueError:
                result["max_age"] = None
        result["mx"] = mx
    except Exception:
        # The DNS record exists but the policy file could not be retrieved:
        # leave policy_present as None (unknown) rather than claiming the
        # domain published no policy.
        result["policy_present"] = None
    return result


def _dmarc(domain: str, timeout: int) -> tuple[dict, dict]:
    """Parse the DMARC record's finer tags.

    Returns ``(detail, meta)``. ``detail`` has exactly the reported keys
    (``sp``, ``aspf``, ``adkim``, ``ruf``, ``fo``, ``pct``); ``meta`` carries
    the ``p=`` policy and lookup outcome used for the issues and score, which
    are deliberately not part of the reported detail dict.
    """
    detail = {"sp": None, "aspf": None, "adkim": None, "ruf": False, "fo": None, "pct": None}
    meta = {"present": None, "policy": None, "record": None, "lookup_failed": False}

    records, status = _txt(f"_dmarc.{domain}", timeout)
    if status == "failed":
        meta["lookup_failed"] = True
        return detail, meta
    if status != "ok":
        meta["present"] = False
        return detail, meta

    record = next((r for r in records if r.lower().startswith("v=dmarc1")), None)
    if not record:
        meta["present"] = False
        return detail, meta

    meta["present"] = True
    meta["record"] = record[:300]
    policy = re.search(r"\bp\s*=\s*(none|quarantine|reject)", record, re.IGNORECASE)
    meta["policy"] = policy.group(1).lower() if policy else "unspecified"

    for key in ("sp", "aspf", "adkim", "fo"):
        found = re.search(rf"\b{key}\s*=\s*([A-Za-z0-9_.:/]+)", record, re.IGNORECASE)
        if found:
            detail[key] = found.group(1).lower()
    detail["ruf"] = bool(re.search(r"\bruf\s*=", record, re.IGNORECASE))
    pct = re.search(r"\bpct\s*=\s*(\d+)", record, re.IGNORECASE)
    if pct:
        detail["pct"] = int(pct.group(1))
    return detail, meta


def analyze(domain: str, timeout: int = 5) -> dict:
    """Full email-authentication depth for a domain.

    Returns a dict with the keys ``domain``, ``bimi``, ``tls_rpt``, ``dkim``,
    ``mta_sts``, ``dmarc_detail``, ``issues`` and ``score``.

    Presence flags are tri-state: ``None`` means the lookup did not complete,
    so absence is *not* established. ``score`` is a simple 0-100 posture
    indicator, not a severity rating.
    """
    domain = (domain or "").strip().rstrip(".").lower()
    issues: list[str] = []

    bimi = _bimi(domain, timeout)
    tls_rpt = _tls_rpt(domain, timeout)
    dkim, dkim_lookup_failed = _dkim(domain, timeout)
    mta_sts = _mta_sts(domain, timeout)
    dmarc_detail, dmarc_meta = _dmarc(domain, timeout)

    # --- DMARC ---------------------------------------------------------
    if dmarc_meta["lookup_failed"]:
        issues.append(
            "DMARC lookup did not complete (DNS timeout or resolver error) - absence is NOT established."
        )
    elif dmarc_meta["present"] is False:
        issues.append(
            "No DMARC record published - receivers have no instruction on what to do with mail that fails SPF/DKIM."
        )
    elif dmarc_meta["policy"] == "none":
        issues.append("DMARC policy is 'p=none' (monitor only) - failing mail is still delivered.")
    elif dmarc_meta["policy"] == "unspecified":
        issues.append("DMARC record present but no p= policy tag found.")

    if dmarc_meta["present"] and dmarc_detail["pct"] is not None and dmarc_detail["pct"] < 100:
        issues.append(
            f"DMARC policy is applied to only {dmarc_detail['pct']}% of mail (pct=), so most failing mail is unaffected."
        )
    if dmarc_meta["present"] and dmarc_detail["sp"] == "none":
        issues.append("DMARC subdomain policy 'sp=none' lets subdomains send unauthenticated mail.")

    # --- Transport security -------------------------------------------
    if tls_rpt["present"] is None:
        issues.append(
            "TLS-RPT lookup did not complete (DNS timeout or resolver error) - absence is NOT established."
        )
    elif tls_rpt["present"] is False:
        issues.append(
            "No TLS-RPT record (_smtp._tls) - the domain receives no reports when inbound mail is delivered without TLS."
        )

    if mta_sts["dns_present"] is None:
        issues.append("MTA-STS DNS lookup did not complete - absence is NOT established.")
    elif mta_sts["dns_present"] is False:
        issues.append(
            "No MTA-STS DNS record (_mta-sts) - senders have no policy telling them to require TLS."
        )
    elif mta_sts["policy_present"] is None:
        issues.append(
            "MTA-STS DNS record is published but the policy file could not be retrieved - policy enforcement is unconfirmed."
        )
    elif mta_sts["policy_present"] is False:
        issues.append(
            "MTA-STS DNS record published but no policy file was served at "
            "/.well-known/mta-sts.txt - the record alone enforces nothing."
        )
    elif mta_sts["mode"] in (None, "none", "testing"):
        issues.append(
            f"MTA-STS policy mode is '{mta_sts['mode'] or 'unspecified'}' - senders are not required to enforce TLS."
        )

    # --- Brand indicators ---------------------------------------------
    if bimi["present"] is None:
        issues.append("BIMI lookup did not complete (DNS timeout or resolver error) - absence is NOT established.")
    elif bimi["present"] is False:
        issues.append("No BIMI record (_bimi) - cosmetic only; providers will not display a verified logo.")

    # --- DKIM ----------------------------------------------------------
    if dkim_lookup_failed:
        issues.append(
            "One or more DKIM selector lookups did not complete (DNS timeout or resolver error) - results may be incomplete."
        )
    if not dkim["selectors_found"]:
        issues.append(
            "No DKIM key found for the common selectors checked - this proves nothing (selectors are arbitrary), "
            "but none of the well-known ones resolved."
        )
    weak = sorted(selector for selector, bits in dkim["key_bits"].items() if 0 < bits < _WEAK_KEY_BITS)
    if weak:
        issues.append(
            f"DKIM key(s) shorter than {_WEAK_KEY_BITS} bits for selector(s): {', '.join(weak)} - small keys are brute-forceable."
        )
    revoked = sorted(selector for selector, bits in dkim["key_bits"].items() if bits == 0)
    if revoked:
        issues.append(
            f"DKIM selector(s) published with an empty p= (revoked key): {', '.join(revoked)}."
        )

    # Score is a simple posture indicator, not a severity rating.
    score = 0
    if dmarc_meta["present"] and dmarc_meta["policy"] in ("quarantine", "reject"):
        score += 35
    elif dmarc_meta["present"]:
        score += 10
    if mta_sts["dns_present"]:
        score += 10
    if mta_sts["policy_present"] and mta_sts["mode"] == "enforce":
        score += 20
    elif mta_sts["policy_present"] and mta_sts["mode"] == "testing":
        score += 10
    if tls_rpt["present"]:
        score += 15
    if bimi["present"]:
        score += 10
    if dkim["selectors_found"]:
        score += 10

    return {
        "domain": domain,
        "bimi": bimi,
        "tls_rpt": tls_rpt,
        "dkim": dkim,
        "mta_sts": mta_sts,
        "dmarc_detail": dmarc_detail,
        "issues": issues,
        "score": min(100, score),
    }
