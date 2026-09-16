# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Email security posture from DNS records.

Missing or weak SPF/DMARC is one of the most commonly reported findings
in bug bounty programs that accept them, and it's entirely passive - the
records are public DNS, so this adds real signal for the cost of a few
TXT lookups and no requests to the target at all.

Everything here reports what the published policy *is*, plus why it
matters. It does not attempt to send mail, spoof anything, or verify
deliverability - that would be testing, not recon.
"""

from __future__ import annotations

import re
from typing import Optional

# Common DKIM selectors published by major providers. Checking a short
# fixed list is cheap; absence here does NOT mean DKIM is unconfigured,
# only that none of these well-known selectors resolved.
_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


def _txt_records(hostname: str, timeout: int = 3) -> tuple[list[str], bool]:
    """Return (records, lookup_ok).

    Distinguishing "resolved, no such record" from "lookup failed" matters:
    reporting a DNS timeout as "no SPF record published" is a confidently
    wrong security claim, and exactly the kind of false finding that makes
    a report untrustworthy. NXDOMAIN/NoAnswer are genuine absence;
    timeouts and resolver errors are not.
    """
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "TXT", lifetime=timeout)
        return [str(r).strip('"').replace('" "', "") for r in answers], True
    except Exception as exc:
        import dns.resolver
        # These two mean the lookup genuinely succeeded and the record is absent.
        if isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
            return [], True
        return [], False


def _has_record(hostname: str, rtype: str, timeout: int = 3) -> bool:
    try:
        import dns.resolver
        dns.resolver.resolve(hostname, rtype, lifetime=timeout)
        return True
    except Exception:
        return False


def analyze_spf(domain: str, timeout: int = 3) -> dict:
    """Parse the SPF record and flag the two weak terminators.

    `?all` (neutral) and `+all` (pass-all) provide no protection - `+all`
    in particular explicitly authorises the entire internet to send as
    this domain. `~all` (softfail) is the common, reasonable setting;
    `-all` (hardfail) is strictest.
    """
    all_records, lookup_ok = _txt_records(domain, timeout)
    if not lookup_ok:
        return {"present": None, "policy": None, "issue": None,
                "lookup_failed": True,
                "note": "SPF lookup did not complete (DNS timeout or resolver error) - absence is NOT established."}
    records = [r for r in all_records if r.lower().startswith("v=spf1")]
    if not records:
        return {
            "present": False,
            "policy": None,
            "issue": "No SPF record published - anyone can send mail claiming to be this domain without SPF failing.",
        }

    record = records[0]
    if len(records) > 1:
        # Multiple SPF records is itself a misconfiguration: RFC 7208 says
        # receivers must treat this as permerror, so SPF effectively fails open.
        return {
            "present": True,
            "record": record[:200],
            "policy": "invalid",
            "issue": f"{len(records)} SPF records published - RFC 7208 requires exactly one, so evaluation returns permerror.",
        }

    match = re.search(r"([-~?+])all\b", record, re.IGNORECASE)
    qualifier = match.group(1) if match else None
    policy_map = {"-": "hardfail", "~": "softfail", "?": "neutral", "+": "pass-all"}
    policy = policy_map.get(qualifier, "none")

    issue = None
    if policy == "pass-all":
        issue = "SPF ends in '+all', which authorises ANY host to send mail as this domain."
    elif policy == "neutral":
        issue = "SPF ends in '?all' (neutral), which provides no enforcement."
    elif policy == "none":
        issue = "SPF record has no 'all' mechanism, so unlisted senders are not covered."

    return {"present": True, "record": record[:200], "policy": policy, "issue": issue}


def analyze_dmarc(domain: str, timeout: int = 3) -> dict:
    """Parse the DMARC policy at _dmarc.<domain>."""
    all_records, lookup_ok = _txt_records(f"_dmarc.{domain}", timeout)
    if not lookup_ok:
        return {"present": None, "policy": None, "issue": None,
                "lookup_failed": True,
                "note": "DMARC lookup did not complete (DNS timeout or resolver error) - absence is NOT established."}
    records = [r for r in all_records if r.lower().startswith("v=dmarc1")]
    if not records:
        return {
            "present": False,
            "policy": None,
            "issue": "No DMARC record published - receivers have no instruction on what to do with mail that fails SPF/DKIM.",
        }

    record = records[0]
    policy_match = re.search(r"\bp\s*=\s*(none|quarantine|reject)", record, re.IGNORECASE)
    policy = policy_match.group(1).lower() if policy_match else "unspecified"
    pct_match = re.search(r"\bpct\s*=\s*(\d+)", record, re.IGNORECASE)
    pct = int(pct_match.group(1)) if pct_match else 100

    issue = None
    if policy == "none":
        issue = "DMARC policy is 'p=none' (monitor only) - failing mail is still delivered."
    elif policy == "unspecified":
        issue = "DMARC record present but no p= policy tag found."
    elif pct < 100:
        issue = f"DMARC policy '{policy}' is only applied to {pct}% of mail."

    return {
        "present": True,
        "record": record[:200],
        "policy": policy,
        "pct": pct,
        "rua": bool(re.search(r"\brua\s*=", record, re.IGNORECASE)),
        "issue": issue,
    }


def check_dkim(domain: str, timeout: int = 3) -> dict:
    """Check a short list of well-known DKIM selectors."""
    found = []
    for selector in _DKIM_SELECTORS:
        records, _ = _txt_records(f"{selector}._domainkey.{domain}", timeout)
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in records):
            found.append(selector)
    return {
        "selectors_found": found,
        "note": (
            "DKIM selectors are arbitrary - absence here only means none of the "
            "common selectors resolved, not that DKIM is unconfigured."
        ),
    }


def check_mta_sts(domain: str, timeout: int = 3) -> dict:
    """MTA-STS and TLS-RPT presence (both published via DNS)."""
    mta_sts = [r for r in _txt_records(f"_mta-sts.{domain}", timeout)[0] if "v=STSv1" in r]
    tls_rpt = [r for r in _txt_records(f"_smtp._tls.{domain}", timeout)[0] if "v=TLSRPTv1" in r]
    return {"mta_sts": bool(mta_sts), "tls_rpt": bool(tls_rpt)}


def analyze(domain: str, timeout: int = 3) -> dict:
    """Full email security posture for a domain."""
    spf = analyze_spf(domain, timeout)
    dmarc = analyze_dmarc(domain, timeout)
    dkim = check_dkim(domain, timeout)
    transport = check_mta_sts(domain, timeout)
    has_mx = _has_record(domain, "MX", timeout)

    issues = [item["issue"] for item in (spf, dmarc) if item.get("issue")]

    # Score is a simple posture indicator, not a severity rating.
    score = 0
    if spf["present"] and spf.get("policy") in ("hardfail", "softfail"):
        score += 35
    elif spf["present"]:
        score += 10
    if dmarc["present"] and dmarc.get("policy") in ("quarantine", "reject"):
        score += 40
    elif dmarc["present"]:
        score += 15
    if dkim["selectors_found"]:
        score += 15
    if transport["mta_sts"]:
        score += 10

    return {
        "domain": domain,
        "has_mx": has_mx,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "transport": transport,
        "issues": issues,
        "score": min(100, score),
    }
