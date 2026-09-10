"""Optional read-only MCP server for Inoue catalog and scan workflows."""

from __future__ import annotations

import json
from typing import Any

from core.scanner import scan
from fingerprints.signatures import SIGNATURES

try:  # pragma: no cover - optional integration dependency
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    FastMCP = None


def search_signatures(query: str, category: str | None = None) -> list[dict[str, Any]]:
    """Search the local signature catalog without making network requests."""
    needle = query.strip().lower()
    matches = []
    for name, signature in SIGNATURES.items():
        if needle not in name.lower():
            continue
        if category and signature.get("category") != category:
            continue
        matches.append({
            "name": name,
            "category": signature.get("category", "Other"),
            "signals": sorted(key for key in signature if key in {"headers", "cookies", "html", "scripts", "meta", "paths"}),
        })
    return sorted(matches, key=lambda item: item["name"])


def catalog_summary() -> dict[str, Any]:
    """Return catalog counts grouped by category."""
    categories: dict[str, int] = {}
    for signature in SIGNATURES.values():
        category = signature.get("category", "Other")
        categories[category] = categories.get(category, 0) + 1
    return {"count": len(SIGNATURES), "categories": dict(sorted(categories.items()))}


def scan_target(target: str, modules: list[str] | None = None, timeout: int = 10) -> dict[str, Any]:
    """Run the existing read-only scanner and return JSON-compatible output."""
    result = scan(target, timeout=timeout, modules=modules)
    return {
        "url": result.final_url,
        "status_code": result.status_code,
        "response_time_ms": result.response_time_ms,
        "technologies": [technology.__dict__ for technology in result.technologies],
        "notes": result.notes,
        "error": result.error,
    }


if FastMCP is not None:  # pragma: no cover - exercised by MCP clients
    mcp = FastMCP("inoue")

    @mcp.tool()
    def search_catalog(query: str, category: str | None = None) -> str:
        return json.dumps(search_signatures(query, category), sort_keys=True)

    @mcp.tool()
    def get_catalog_summary() -> str:
        return json.dumps(catalog_summary(), sort_keys=True)

    @mcp.tool()
    def scan_read_only(target: str, modules: list[str] | None = None, timeout: int = 10) -> str:
        return json.dumps(scan_target(target, modules, timeout), sort_keys=True)
else:
    mcp = None


def main() -> None:
    if mcp is None:
        raise SystemExit("MCP support is optional; install with: python -m pip install 'inoue[mcp]'")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
