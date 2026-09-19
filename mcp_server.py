"""Optional read-only MCP server for Inoue catalog and scan workflows.

Model-agnostic by design: this is a standard Model Context Protocol
server built on the official `mcp` Python SDK, so any MCP-compatible
client can use it - Claude Desktop, Claude Code, or any other client
that implements the MCP spec - not anything Claude-specific.

Two things make that true in practice rather than just in principle:

1. **SDK compatibility.** The `mcp` package renamed its core server class
   from `FastMCP` (v1, `mcp.server.fastmcp`) to `MCPServer` (v2,
   `mcp.server.mcpserver`) with the same public `.tool()`/`.run()` API.
   A version-unaware `mcp>=1.0` install today pulls v2, and the old
   single-path import silently failed (caught by a bare `except
   ImportError`, which is what `ModuleNotFoundError` is) with a
   misleading "not installed" message even when it WAS installed - the
   version just didn't match. This module tries both import paths and
   surfaces the real reason when neither works.
2. **Transport.** stdio-only servers only work with clients that can
   spawn a local subprocess. `streamable-http` and `sse` let any
   HTTP-capable MCP client connect too - a web-based client, a remote
   agent, anything that isn't spawning Inoue as a child process. Pick
   the transport with `--transport` or `INOUE_MCP_TRANSPORT`.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import httpx

from core.history import DEFAULT_HISTORY_PATH, list_snapshots
from core.scanner import scan
from core.security_grade import detect_cors_misconfig, grade_security_headers
from core.waf import detect_waf
from fingerprints.signatures import SIGNATURES

_MCP_IMPORT_ERROR: str | None = None
MCPServerBase = None


def _import_mcp_server_base(import_v2=None, import_v1=None):
    """Resolve a usable MCP server class from whichever SDK version is
    installed. Factored out as a pure function (rather than inline
    module-level try/except) so the fallback and total-failure paths are
    independently testable without reloading this whole module - a reload
    would re-run every side effect below, including instantiating a real
    server and re-registering every tool, which is fragile to test against.

    `import_v2`/`import_v1` are injectable for tests; production code
    leaves them as the real imports.
    """
    def _default_import_v2():
        from mcp.server.mcpserver import MCPServer
        return MCPServer

    def _default_import_v1():
        from mcp.server.fastmcp import FastMCP
        return FastMCP

    import_v2 = import_v2 or _default_import_v2
    import_v1 = import_v1 or _default_import_v1

    try:  # v2 SDK (current): mcp.server.mcpserver.MCPServer
        return import_v2(), None
    except ImportError as exc:
        v2_error = str(exc)
    try:  # v1 SDK (legacy): mcp.server.fastmcp.FastMCP - same public API
        return import_v1(), None
    except ImportError as exc2:
        return None, (
            f"Neither the v2 ({v2_error}) nor v1 ({exc2}) MCP server class could be "
            "imported. Install a compatible SDK with: python -m pip install 'inoue[mcp]'"
        )


MCPServerBase, _MCP_IMPORT_ERROR = _import_mcp_server_base()

# Kept for backward compatibility with anything importing FastMCP directly.
FastMCP = MCPServerBase


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
        "waf": result.waf,
        "notes": result.notes,
        "error": result.error,
    }


def _lightweight_fetch(target: str, timeout: int = 8) -> tuple[dict, dict]:
    """A single bare GET - headers + cookies only, no fingerprinting, no
    recon modules. Used by the check_waf/check_security_headers tools so
    they stay fast even when a full scan_read_only call would be overkill."""
    url = target if target.startswith(("http://", "https://")) else f"https://{target}"
    with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
        response = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    return dict(response.headers), {k: v for k, v in response.cookies.items()}


def check_waf(target: str, timeout: int = 8) -> list[dict[str, Any]]:
    """Passive WAF/CDN check only - one request, no fingerprint catalog match."""
    headers, cookies = _lightweight_fetch(target, timeout=timeout)
    return detect_waf(headers, cookies)


def check_security_headers(target: str, timeout: int = 8) -> dict[str, Any]:
    """Security header grade + CORS misconfiguration check - one request."""
    headers, _ = _lightweight_fetch(target, timeout=timeout)
    return {
        "grade": grade_security_headers(headers),
        "cors_misconfig": detect_cors_misconfig(headers),
    }


def get_scan_history(target: str, limit: int = 10) -> list[dict[str, Any]]:
    """Read previously saved scan snapshots for a target (see --save-history
    in the CLI). Read-only - this never triggers a new scan."""
    normalized = target if target.startswith(("http://", "https://")) else f"https://{target}"
    snapshots = list_snapshots(DEFAULT_HISTORY_PATH, normalized, limit=limit)
    return [{"scanned_at": s["scanned_at"], "technology_count": len(s["result"].get("technologies", []))} for s in snapshots]


def check_technology_eol(name: str, version: str) -> dict[str, Any]:
    """Check a technology+version against Inoue's static, verified EOL
    table. Returns {"checked": False} for anything not in the table -
    absence never means "not EOL", only "not checked"."""
    from core.eol import check_eol
    result = check_eol(name, version)
    if result is None:
        return {"checked": False, "name": name, "version": version}
    return {"checked": True, **result}


if MCPServerBase is not None:  # pragma: no cover - exercised by MCP clients
    mcp = MCPServerBase("inoue")

    @mcp.tool()
    def search_catalog(query: str, category: str | None = None) -> str:
        """Search Inoue's local technology signature catalog by name, optionally filtered by category. No network requests."""
        return json.dumps(search_signatures(query, category), sort_keys=True)

    @mcp.tool()
    def get_catalog_summary() -> str:
        """Return signature counts grouped by category from the local catalog. No network requests."""
        return json.dumps(catalog_summary(), sort_keys=True)

    @mcp.tool()
    def scan_read_only(target: str, modules: list[str] | None = None, timeout: int = 10) -> str:
        """Run a read-only technology fingerprint scan against a target URL or hostname. No exploitation, no writes, no credential automation."""
        return json.dumps(scan_target(target, modules, timeout), sort_keys=True)

    @mcp.tool()
    def check_waf_tool(target: str, timeout: int = 8) -> str:
        """Fast, passive-only WAF/CDN check against a target (one request, headers/cookies only - no full scan)."""
        return json.dumps(check_waf(target, timeout), sort_keys=True)

    @mcp.tool()
    def check_security_headers_tool(target: str, timeout: int = 8) -> str:
        """Fast security-header grade and CORS misconfiguration check against a target (one request)."""
        return json.dumps(check_security_headers(target, timeout), sort_keys=True)

    @mcp.tool()
    def get_scan_history_tool(target: str, limit: int = 10) -> str:
        """Read previously saved scan history for a target from the local history DB. Never triggers a new scan."""
        return json.dumps(get_scan_history(target, limit), sort_keys=True)

    @mcp.tool()
    def check_eol_tool(name: str, version: str) -> str:
        """Check a technology name and version against Inoue's static, verified end-of-life table. No network requests."""
        return json.dumps(check_technology_eol(name, version), sort_keys=True)
else:
    mcp = None


def main() -> None:
    if mcp is None:
        raise SystemExit(_MCP_IMPORT_ERROR or "MCP support is optional; install with: python -m pip install 'inoue[mcp]'")

    parser = argparse.ArgumentParser(prog="inoue-mcp", description="Inoue read-only MCP server.")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default=os.getenv("INOUE_MCP_TRANSPORT", "stdio"),
        help="Transport to serve over. stdio (default) works with clients that spawn a local "
             "subprocess (Claude Desktop, Claude Code). sse/streamable-http serve over HTTP for "
             "any other MCP-compatible client. Can also be set via INOUE_MCP_TRANSPORT.",
    )
    args = parser.parse_args()

    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
