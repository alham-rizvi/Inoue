# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
API surface discovery.

Checks a small, fixed set of conventional API-documentation paths rather
than brute-forcing a wordlist - these are near-universal framework
defaults (`/swagger.json`, `/openapi.json`, `/.well-known/security.txt`),
so probing them is cheap, bounded, and stays firmly in recon territory.

For GraphQL, the finding that matters is whether **introspection is
enabled**: an exposed introspection endpoint hands an attacker the full
schema, which is a legitimate, commonly-reported finding on its own. We
send exactly one minimal introspection query to determine that, and stop
there - we never enumerate the schema or chain further queries off it.
"""

from __future__ import annotations

import json
from typing import Optional
from urllib.parse import urljoin

import httpx

# Conventional, framework-default documentation paths.
_API_DOC_PATHS = [
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api-docs",
    "/v1/openapi.json",
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
]

_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

# The smallest query that reveals whether introspection is on.
_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name}}}"}


def _probe(url: str, timeout: int) -> Optional[httpx.Response]:
    try:
        with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
            return client.get(url, headers={"User-Agent": "Mozilla/5.0"})
    except Exception:
        return None


def discover_api_docs(base_url: str, timeout: int = 6) -> list[dict]:
    """Probe conventional API documentation paths."""
    findings = []
    for path in _API_DOC_PATHS:
        url = urljoin(base_url, path)
        response = _probe(url, timeout)
        if response is None or response.status_code != 200:
            continue
        body = response.text[:20_000]
        content_type = response.headers.get("content-type", "")

        kind = "unknown"
        detail = ""
        if path.endswith("security.txt"):
            kind = "security.txt"
            detail = "Security contact policy published."
        elif "openid-configuration" in path:
            kind = "OpenID Connect discovery"
            detail = "OIDC configuration exposed (normal for an IdP)."
        elif "json" in content_type or body.lstrip().startswith("{"):
            try:
                payload = json.loads(body)
                if "swagger" in payload or "openapi" in payload:
                    kind = "OpenAPI/Swagger spec"
                    version = payload.get("openapi") or payload.get("swagger")
                    title = (payload.get("info") or {}).get("title", "")
                    detail = f"spec version {version}" + (f", title: {title}" if title else "")
                    paths_count = len(payload.get("paths") or {})
                    if paths_count:
                        detail += f", {paths_count} documented paths"
                else:
                    continue  # JSON but not a spec - not worth reporting
            except (json.JSONDecodeError, AttributeError):
                continue
        elif "api-docs" in path and "swagger" in body.lower():
            kind = "Swagger UI"
            detail = "Interactive API docs page."
        else:
            continue

        findings.append({
            "url": url,
            "kind": kind,
            "status_code": response.status_code,
            "detail": detail,
        })
    return findings


def check_graphql_introspection(base_url: str, timeout: int = 6) -> list[dict]:
    """Detect GraphQL endpoints and whether introspection is enabled.

    Introspection being enabled is itself the finding - we report it and
    stop. No schema enumeration, no follow-up queries.
    """
    findings = []
    for path in _GRAPHQL_PATHS:
        url = urljoin(base_url, path)
        try:
            with httpx.Client(timeout=timeout, verify=False, follow_redirects=True) as client:
                response = client.post(
                    url,
                    json=_INTROSPECTION_QUERY,
                    headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
                )
        except Exception:
            continue

        if response.status_code not in (200, 400):
            continue
        body = response.text[:10_000]
        if "__schema" not in body and "GraphQL" not in body and "errors" not in body:
            continue

        introspection_enabled = False
        try:
            payload = response.json()
            introspection_enabled = bool((payload.get("data") or {}).get("__schema"))
        except Exception:
            pass

        findings.append({
            "url": url,
            "status_code": response.status_code,
            "introspection_enabled": introspection_enabled,
            "detail": (
                "Introspection is ENABLED - the full schema is readable by anyone."
                if introspection_enabled
                else "GraphQL endpoint present; introspection appears disabled or restricted."
            ),
        })
        break  # one GraphQL endpoint is enough; don't hammer every path
    return findings


def discover(base_url: str, timeout: int = 6) -> dict:
    """Run the full API surface discovery pass."""
    docs = discover_api_docs(base_url, timeout=timeout)
    graphql = check_graphql_introspection(base_url, timeout=timeout)
    return {
        "api_docs": docs,
        "graphql": graphql,
        "summary": {
            "docs_found": len(docs),
            "graphql_endpoints": len(graphql),
            "introspection_enabled": any(g["introspection_enabled"] for g in graphql),
        },
    }
