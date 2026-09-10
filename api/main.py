from __future__ import annotations

import os
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
    target: str = Field(..., description="Target URL or hostname")
    timeout: int = 10
    follow_redirects: bool = True
    modules: Optional[list[str]] = None
    cve_min_severity: Optional[str] = None


class BatchRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1)
    timeout: int = 10
    follow_redirects: bool = True
    modules: Optional[list[str]] = None
    cve_min_severity: Optional[str] = None
    workers: int = 5
    rate_limit: Optional[float] = None


def create_app() -> Optional[FastAPI]:
    if FastAPI is None:
        return None

    app = FastAPI(title="Inoue API", version="1.0.0")
    max_batch_size = int(os.getenv("INOUE_API_MAX_BATCH_SIZE", "25"))
    api_key = os.getenv("INOUE_API_KEY")

    @app.middleware("http")
    async def enforce_api_key(request: Request, call_next):
        if not api_key:
            return await call_next(request)
        provided = request.headers.get("x-api-key")
        if provided != api_key:
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/signatures")
    async def signatures():
        from fingerprints.signatures import SIGNATURES
        return {"count": len(SIGNATURES), "signatures": sorted(SIGNATURES.keys())[:25]}

    @app.post("/scan")
    async def scan_target(payload: ScanRequest):
        result = scan(
            payload.target,
            timeout=payload.timeout,
            follow_redirects=payload.follow_redirects,
            modules=payload.modules,
            cve_min_severity=payload.cve_min_severity,
        )
        return {
            "url": result.final_url,
            "status_code": result.status_code,
            "technologies": [tech.__dict__ for tech in result.technologies],
            "notes": result.notes,
            "error": result.error,
        }

    @app.post("/scan/batch")
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
            "results": [
                {
                    "url": item.final_url,
                    "status_code": item.status_code,
                    "technologies": [tech.__dict__ for tech in item.technologies],
                    "notes": item.notes,
                    "error": item.error,
                }
                for item in results
            ]
        }

    return app


app = create_app()
