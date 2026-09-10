from __future__ import annotations

import asyncio
import os
import time
from collections import defaultdict
from typing import Any, Optional

try:  # pragma: no cover - optional dependency
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError:  # pragma: no cover - optional dependency
    FastAPI = None  # type: ignore[assignment]
    Request = Any  # type: ignore[assignment]
    HTTPException = Exception  # type: ignore[assignment]
    JSONResponse = None  # type: ignore[assignment]

    class BaseModel:  # type: ignore[override]
        pass

    class Field:  # type: ignore[override]
        def __init__(self, *args, **kwargs):
            pass

from core.scanner import scan, scan_many


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, description="Target URL or hostname")
    timeout: int = Field(10, ge=1, le=120)
    follow_redirects: bool = True
    modules: Optional[list[str]] = None
    cve_min_severity: Optional[str] = None


class BatchRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1)
    timeout: int = Field(10, ge=1, le=120)
    follow_redirects: bool = True
    modules: Optional[list[str]] = None
    cve_min_severity: Optional[str] = None
    workers: int = Field(5, ge=1, le=50)
    rate_limit: Optional[float] = Field(None, gt=0, le=100)


def create_app() -> Optional[FastAPI]:
    if FastAPI is None:
        return None

    app = FastAPI(title="Inoue API", version="1.0.0")
    max_batch_size = int(os.getenv("INOUE_API_MAX_BATCH_SIZE", "25"))
    api_key = os.getenv("INOUE_API_KEY")
    rate_limit_per_second = float(os.getenv("INOUE_API_RATE_LIMIT", "0"))
    client_requests: dict[str, list[float]] = defaultdict(list)

    @app.middleware("http")
    async def enforce_api_key(request: Request, call_next):
        if not api_key:
            pass
        else:
            provided = request.headers.get("x-api-key")
            if provided != api_key:
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)

        if rate_limit_per_second > 0:
            client_id = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip") or (request.client.host if request.client else "unknown")
            now = time.monotonic()
            window = [ts for ts in client_requests.get(client_id, []) if now - ts < 1.0]
            window.append(now)
            client_requests[client_id] = window
            if len(window) > rate_limit_per_second:
                return JSONResponse({"detail": "Rate limit exceeded"}, status_code=429)

        return await call_next(request)

    async def health():
        return {"status": "ok"}

    async def signatures():
        from fingerprints.signatures import SIGNATURES
        return {"count": len(SIGNATURES), "signatures": sorted(SIGNATURES.keys())[:25]}

    def serialize_result(result):
        return {
            "url": result.url,
            "final_url": result.final_url,
            "ip": result.ip,
            "status_code": result.status_code,
            "response_time_ms": result.response_time_ms,
            "server": result.server,
            "technologies": [tech.__dict__ for tech in result.technologies],
            "headers": result.headers,
            "dns": result.dns_records,
            "ssl": result.ssl_info,
            "tls_fingerprint": result.tls_fingerprint,
            "whois": result.whois_info,
            "whois_summary": result.whois_summary,
            "subdomains": result.subdomains,
            "mail_records": result.mail_records,
            "open_ports": result.open_ports,
            "directories": result.directories,
            "extra_intel": result.extra_intel,
            "recon": result.enriched.get("recon", []) if result.enriched else [],
            "service_hints": result.enriched.get("service_hints", []) if result.enriched else [],
            "plugins": result.enriched.get("plugins", {}) if result.enriched else {},
            "notes": result.notes,
            "error": result.error,
            "cache_hit": result.cache_hit,
        }

    async def scan_target(payload: ScanRequest):
        result = await asyncio.to_thread(
            scan,
            payload.target,
            timeout=payload.timeout,
            follow_redirects=payload.follow_redirects,
            modules=payload.modules,
            cve_min_severity=payload.cve_min_severity,
        )
        return serialize_result(result)

    async def scan_batch(payload: BatchRequest):
        if len(payload.targets) > max_batch_size:
            raise HTTPException(status_code=400, detail=f"Batch size exceeds {max_batch_size}")
        results = await scan_many(
            payload.targets,
            timeout=payload.timeout,
            follow_redirects=payload.follow_redirects,
            modules=payload.modules,
            workers=payload.workers,
            rate_limit=payload.rate_limit,
            cve_min_severity=payload.cve_min_severity,
        )
        return {
            "results": [serialize_result(item) for item in results]
        }

    app.get("/health")(health)
    app.get("/signatures")(signatures)
    app.post("/scan")(scan_target)
    app.post("/scan/batch")(scan_batch)
    for prefix in ("/api", "/api/v1"):
        app.get(f"{prefix}/health")(health)
        app.get(f"{prefix}/signatures")(signatures)
        app.post(f"{prefix}/scan")(scan_target)
        app.post(f"{prefix}/scan/batch")(scan_batch)

    return app


app = create_app()
