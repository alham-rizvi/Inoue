# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""Local CVE correlation for detected technology/version pairs."""

import json
from pathlib import Path
from typing import Iterable, Optional


DEFAULT_DATASET = Path(__file__).resolve().parent.parent / "data" / "cves.json"


def load_cve_dataset(path: Optional[str] = None) -> list[dict]:
    dataset_path = Path(path).expanduser() if path else DEFAULT_DATASET
    try:
        payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return payload if isinstance(payload, list) else []


def correlate_cves(name: str, version: Optional[str], dataset: Iterable[dict]) -> list[dict]:
    if not version:
        return []
    matches = []
    for entry in dataset:
        technologies = entry.get("technologies", [entry.get("technology")])
        versions = entry.get("versions", [entry.get("version")])
        if name not in technologies or version not in versions:
            continue
        matches.append({
            "id": entry.get("id", ""),
            "summary": entry.get("summary", ""),
            "severity": entry.get("severity", "unknown"),
        })
    return [item for item in matches if item["id"]]
