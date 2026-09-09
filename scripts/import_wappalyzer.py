#!/usr/bin/env python3
"""Normalize a Wappalyzer technology catalog into Inoue signature entries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import httpx


CATEGORY_NAMES = {
    1: "CMS",
    6: "E-commerce",
    10: "Analytics",
    18: "Framework",
    22: "JavaScript Framework",
}


def _patterns(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, dict):
        return [str(key) for key in value]
    return []


def normalize_technology(name: str, definition: dict[str, Any]) -> dict[str, Any]:
    signature: dict[str, Any] = {
        "category": CATEGORY_NAMES.get((definition.get("cats") or [0])[0], "Other"),
        "source": "wappalyzer-import",
    }
    for source, target in (("html", "html"), ("scripts", "scripts"), ("cookies", "cookies"), ("urls", "paths")):
        values = _patterns(definition.get(source))
        if values:
            signature[target] = values
    headers = definition.get("headers")
    if isinstance(headers, dict):
        normalized_headers = {}
        for header, pattern in headers.items():
            values = _patterns(pattern)
            if values:
                normalized_headers[header] = values[0]
        if normalized_headers:
            signature["headers"] = normalized_headers
    meta = definition.get("meta")
    if isinstance(meta, dict):
        normalized_meta = {}
        for key, pattern in meta.items():
            values = _patterns(pattern)
            if values:
                normalized_meta[key] = values[0]
        if normalized_meta:
            signature["meta"] = normalized_meta
    excludes = _patterns(definition.get("excludes"))
    if excludes:
        signature["excludes"] = excludes
    return signature


def normalize_catalog(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    technologies = payload.get("technologies", payload)
    if not isinstance(technologies, dict):
        raise ValueError("Wappalyzer payload must contain a technologies object")
    return {
        name: normalize_technology(name, definition)
        for name, definition in technologies.items()
        if isinstance(name, str) and isinstance(definition, dict)
    }


def load_source(source: str) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        with httpx.Client(timeout=30, verify=True, follow_redirects=True) as client:
            response = client.get(source)
            response.raise_for_status()
            return response.json()
    return json.loads(Path(source).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Wappalyzer JSON file or HTTPS URL")
    parser.add_argument("--output", help="Write normalized JSON entries to FILE")
    parser.add_argument("--write", action="store_true", help="Allow writing the output file; otherwise print a dry-run diff")
    args = parser.parse_args()
    entries = normalize_catalog(load_source(args.source))
    rendered = json.dumps(entries, indent=2, sort_keys=True) + "\n"
    if args.output and args.write:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"wrote {len(entries)} normalized signature(s) to {args.output}")
    else:
        print(f"dry-run: {len(entries)} normalized signature(s)")
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
