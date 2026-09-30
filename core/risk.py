# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Risk scoring and triage ranking.

Inoue collects a lot of independent signals - CVEs, exposed files, WAF
presence, security-header grade, CORS misconfigurations, takeover
candidates, leaked secrets in JS, open ports. Individually each is a
line in a report. The actual bug-bounty workflow is "I have 200
subdomains, which three should I look at first?", which needs them
combined into one ordered view.

This is a **triage heuristic, not a severity rating**. The score exists
to sort a list, not to claim anything is exploitable. Every contributing
factor is reported alongside the number so the ranking is auditable and
you can disagree with it - a high score means "look here first", never
"this is vulnerable".
"""

from __future__ import annotations

from typing import Any

# (weight, label) - weights are relative sort nudges, deliberately coarse.
_FINDING_WEIGHTS = {
    # A live takeover candidate warrants immediate investigation on its
    # own, so it is weighted to reach the top triage band unaided.
    "takeover_candidate": 60,
    "secret_in_js": 35,
    "critical_cve": 30,
    "eol_technology": 22,
    "exposed_sensitive_file": 25,
    "graphql_introspection": 20,
    "high_cve": 20,
    "cors_misconfig": 18,
    "no_waf": 10,
    "weak_security_headers": 10,
    "openapi_spec_exposed": 8,
    "medium_cve": 8,
    "many_open_ports": 5,
}

_SENSITIVE_PATHS = (".env", ".git", ".ds_store", "docker-compose", ".aws", "backup", ".bak", "id_rsa")

# The v2 exposure module only emits a `findings` entry once its content verifier
# has confirmed the artefact, so a finding is by definition verified. Two things
# are still excluded from the score: `info`-graded findings (an absent
# security.txt is a missing good practice, not an exposure) and the non-file
# kinds below, which are different classes of signal.
_EXPOSURE_UNSCORED_SEVERITIES = ("info",)

# Non-file kinds the exposure module reports alongside its file findings. A
# permissive crossdomain policy and a published source map are real findings,
# but neither is "an exposed sensitive file", so neither may be labelled as one
# in the triage breakdown.
_EXPOSURE_NON_FILE_KINDS = ("security_txt", "crossdomain_policy", "source_map")


def _exposure_findings(exposure) -> list[dict[str, Any]]:
    """Normalise an ``exposure`` payload into the risk-worthy, *verified* findings.

    Two shapes have to be accepted, because ``enriched`` is also populated by
    cached results and by older producers:

    * the v2 ``core.exposure`` payload - a dict whose verified artefacts live in
      ``findings`` (``{"path", "status", "severity", "kind", ...}``) and whose
      ``candidates`` are explicitly *unverified* 200 responses;
    * the older per-item rows - ``{"url": ..., "status_code": 200}``, as a list
      or as a single dict.

    Only verified findings are returned. Letting an unverified candidate drive
    the score would undo the content verification the exposure module performs
    precisely so a catch-all/soft-404 responder is not reported as an exposure.
    """
    if isinstance(exposure, dict):
        findings = exposure.get("findings")
        if findings is None:
            findings = [exposure]
    elif isinstance(exposure, list):
        findings = exposure
    else:
        return []

    normalised: list[dict[str, Any]] = []
    for item in findings or []:
        if not isinstance(item, dict):
            continue
        path = item.get("path") or item.get("url")
        if not path:
            continue
        status = item.get("status", item.get("status_code"))
        severity = str(item.get("severity") or "").lower()
        kind = str(item.get("kind") or "")
        if severity:
            # New shape: the module already decided this is a real artefact, so
            # only its `info` grade and its non-file kinds are filtered out.
            if severity in _EXPOSURE_UNSCORED_SEVERITIES or kind in _EXPOSURE_NON_FILE_KINDS:
                continue
        else:
            # Legacy shape: no severity to trust, so fall back to the
            # path-marker rule the scorer has always used.
            if status != 200 or not any(marker in str(path).lower() for marker in _SENSITIVE_PATHS):
                continue
        normalised.append({"path": str(path), "status": status, "severity": severity or "unknown"})
    return normalised


def _cve_severity_counts(result) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0}
    for tech in getattr(result, "technologies", []) or []:
        for cve in getattr(tech, "cves", []) or []:
            severity = str(cve.get("severity", "")).lower()
            if severity in counts:
                counts[severity] += 1
    return counts


def score_result(result) -> dict[str, Any]:
    """Compute a triage score and the factors behind it for one ScanResult."""
    factors: list[dict[str, Any]] = []
    enriched = getattr(result, "enriched", {}) or {}

    def add(key: str, detail: str):
        factors.append({"factor": key, "weight": _FINDING_WEIGHTS[key], "detail": detail})

    # --- takeover candidates -------------------------------------------------
    takeovers = enriched.get("takeover_candidates") or []
    for candidate in takeovers:
        add("takeover_candidate", f"{candidate.get('hostname')} -> {candidate.get('service')}")

    # --- secrets leaked in JS -------------------------------------------------
    js_intel = enriched.get("js_intel") or {}
    for finding in js_intel.get("secret_findings") or []:
        add("secret_in_js", f"{finding.get('type')} in {finding.get('source', '')[:60]}")

    # --- CVEs -----------------------------------------------------------------
    cve_counts = _cve_severity_counts(result)
    if cve_counts["critical"]:
        add("critical_cve", f"{cve_counts['critical']} critical CVE(s) on detected technologies")
    if cve_counts["high"]:
        add("high_cve", f"{cve_counts['high']} high-severity CVE(s)")
    if cve_counts["medium"]:
        add("medium_cve", f"{cve_counts['medium']} medium-severity CVE(s)")

    # --- end-of-life technologies ---------------------------------------------
    for eol in enriched.get("eol_technologies") or []:
        add("eol_technology", f"{eol['name']} {eol['version']} is EOL ({eol['days_past_eol']}d past {eol['eol_date']})")

    # --- exposed sensitive files ---------------------------------------------
    # Consumes both the v2 exposure payload (verified `findings`) and the older
    # per-item rows - see `_exposure_findings`. Unverified candidates never
    # reach the score.
    for finding in _exposure_findings(enriched.get("exposure")):
        detail = f"{finding['path']} returned {finding['status']}"
        if finding["severity"] != "unknown":
            detail += f" ({finding['severity']})"
        add("exposed_sensitive_file", detail)

    # --- API surface ----------------------------------------------------------
    api_surface = enriched.get("api_surface") or {}
    if (api_surface.get("summary") or {}).get("introspection_enabled"):
        add("graphql_introspection", "GraphQL introspection is enabled")
    # Only count genuinely risk-relevant docs. security.txt is a *good*
    # practice (a published disclosure policy) and an OIDC discovery
    # document is the expected, correct behaviour of an identity provider -
    # neither belongs in a risk score. An openly readable OpenAPI/Swagger
    # spec is the one that actually widens the attack surface.
    risky_docs = [
        doc for doc in (api_surface.get("api_docs") or [])
        if doc.get("kind") in ("OpenAPI/Swagger spec", "Swagger UI")
    ]
    if risky_docs:
        add("openapi_spec_exposed", f"{len(risky_docs)} API spec/doc endpoint(s) publicly readable")

    # --- CORS -----------------------------------------------------------------
    for finding in enriched.get("cors_misconfig") or []:
        add("cors_misconfig", finding.get("issue", "CORS misconfiguration"))

    # --- WAF ------------------------------------------------------------------
    if not (getattr(result, "waf", None) or []):
        add("no_waf", "No WAF/CDN detected in front of this host")

    # --- security headers ------------------------------------------------------
    grade = enriched.get("security_grade") or {}
    if grade and grade.get("score", 100) < 50:
        add("weak_security_headers", f"Security header score {grade.get('score')}/100")

    # --- open ports ------------------------------------------------------------
    open_ports = getattr(result, "open_ports", []) or []
    if len(open_ports) > 5:
        add("many_open_ports", f"{len(open_ports)} open ports")

    score = min(100, sum(f["weight"] for f in factors))
    if score >= 60:
        band = "investigate-first"
    elif score >= 30:
        band = "worth-a-look"
    elif score > 0:
        band = "low-signal"
    else:
        band = "nothing-notable"

    return {
        "score": score,
        "band": band,
        "factors": sorted(factors, key=lambda f: -f["weight"]),
        "caveat": "Triage heuristic for ordering targets - not a severity rating or a vulnerability claim.",
    }


def rank_results(results: list) -> list[dict[str, Any]]:
    """Rank many ScanResults highest-signal-first for fast triage."""
    ranked = []
    for result in results:
        if getattr(result, "error", None):
            continue
        scored = score_result(result)
        ranked.append({
            "target": getattr(result, "final_url", None) or getattr(result, "url", ""),
            "score": scored["score"],
            "band": scored["band"],
            "top_factors": [f["detail"] for f in scored["factors"][:3]],
        })
    return sorted(ranked, key=lambda item: -item["score"])
