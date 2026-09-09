# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""Local CVE correlation for detected technology/version pairs."""

import json
import gzip
import os
import re
from pathlib import Path
from typing import Iterable, Optional

import httpx


DEFAULT_DATASET = Path(__file__).resolve().parent.parent / "data" / "cves.json"


def load_cve_dataset(path: Optional[str] = None) -> list[dict]:
    dataset_path = Path(path).expanduser() if path else DEFAULT_DATASET
    try:
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return payload if isinstance(payload, list) else []


SEVERITY_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def correlate_cves(
    name: str,
    version: Optional[str],
    dataset: Iterable[dict],
    min_severity: Optional[str] = None,
) -> list[dict]:
    if not version:
        return []
    matches = []
    for entry in dataset:
        technologies = entry.get("technologies", [entry.get("technology")])
        versions = entry.get("versions", [entry.get("version")])
        affected = entry.get("affected")
        exact_match = version in versions
        range_match = _version_in_range(version, affected) if affected else False
        if name not in technologies or not (exact_match or range_match):
            continue
        severity = str(entry.get("severity", "unknown")).lower()
        if min_severity and SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK.get(min_severity.lower(), 0):
            continue
        matches.append({
            "id": entry.get("id", ""),
            "summary": entry.get("summary", ""),
            "severity": severity,
        })
    return sorted(
        (item for item in matches if item["id"]),
        key=lambda item: SEVERITY_RANK.get(item["severity"], 0),
        reverse=True,
    )


def _version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", value))


def _version_in_range(version: str, expression: str) -> bool:
    candidate = _version_tuple(version)
    if not candidate or not expression:
        return False
    for clause in expression.split(","):
        match = re.fullmatch(r"\s*(<=|>=|<|>|=)?\s*([\w.-]+)\s*", clause)
        if not match:
            return False
        operator = match.group(1) or "="
        boundary = _version_tuple(match.group(2))
        if not boundary:
            return False
        if operator == "<" and not candidate < boundary:
            return False
        if operator == "<=" and not candidate <= boundary:
            return False
        if operator == ">" and not candidate > boundary:
            return False
        if operator == ">=" and not candidate >= boundary:
            return False
        if operator == "=" and not candidate == boundary:
            return False
    return True


def _severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            level = entries[0].get("cvssData", {}).get("baseSeverity")
            if level:
                return str(level).lower()
    return "unknown"


def _technology_versions(cve: dict) -> tuple[list[str], list[str]]:
    technologies = set()
    versions = set()
    for node in cve.get("configurations", {}).get("nodes", []):
        for match in node.get("cpeMatch", []):
            criteria = match.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) < 6:
                continue
            product = parts[4].replace("_", " ")
            version = parts[5]
            if product and product != "*":
                technologies.add(product)
            if version and version not in {"*", "-"}:
                versions.add(version)
    return sorted(technologies), sorted(versions)


def refresh_cve_dataset(source_url: Optional[str] = None, output_path: Optional[str] = None) -> int:
    """Refresh the local dataset from an NVD 2.0 JSON feed over verified TLS."""
    feed_url = source_url or os.getenv(
        "INOUE_CVE_FEED_URL",
        "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.gz",
    )
    destination = Path(output_path).expanduser() if output_path else DEFAULT_DATASET
    with httpx.Client(timeout=60, verify=True, follow_redirects=True) as client:
        response = client.get(feed_url)
        response.raise_for_status()
    content = response.content
    if content[:2] == b"\x1f\x8b":
        content = gzip.decompress(content)
    payload = json.loads(content.decode("utf-8"))
    entries = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        summary = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
        technologies, versions = _technology_versions(cve)
        if technologies and versions:
            entries.append({
                "id": cve_id,
                "technologies": technologies,
                "versions": versions,
                "summary": summary,
                "severity": _severity(cve),
            })
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return len(entries)
