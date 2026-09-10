#!/usr/bin/env python3
"""Report signature provenance records that need catalog maintenance."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta
from typing import Iterable

from fingerprints.signatures import SIGNATURES


def audit_signatures(
    catalog: dict[str, dict],
    stale_days: int,
    today: date | None = None,
) -> list[dict[str, str]]:
    reference = today or date.today()
    cutoff = reference - timedelta(days=max(0, stale_days))
    findings = []
    for name, signature in sorted(catalog.items()):
        source = signature.get("source", "unknown")
        since = signature.get("since")
        last_verified = signature.get("last_verified")
        if not last_verified:
            reason = "missing last_verified"
        else:
            try:
                verified_date = datetime.strptime(str(last_verified), "%Y-%m-%d").date()
            except ValueError:
                reason = "invalid last_verified"
            else:
                if verified_date < cutoff:
                    reason = f"last_verified before {cutoff.isoformat()}"
                else:
                    continue
        findings.append({
            "name": name,
            "source": str(source),
            "since": str(since or "unknown"),
            "last_verified": str(last_verified or "unknown"),
            "reason": reason,
        })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stale-days", type=int, default=180)
    args = parser.parse_args()
    findings = audit_signatures(SIGNATURES, args.stale_days)
    if not findings:
        print("all signatures have current provenance metadata")
        return 0
    for finding in findings:
        print(
            f"{finding['name']}: {finding['reason']} "
            f"(source={finding['source']}, since={finding['since']})"
        )
    print(f"{len(findings)} signature(s) need provenance review")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
