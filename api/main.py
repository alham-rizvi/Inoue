from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
import time
from collections import defaultdict
from typing import Any, Optional
from urllib.parse import urlparse

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

from core.scanner import scan, scan_many, serialize_scan_result


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, description="Target URL or hostname")
    timeout: int = Field(10, ge=1, le=120)
    follow_redirects: bool = True
    modules: Optional[list[str]] = None
    cve_min_severity: Optional[str] = None
    crawl_pages: int = Field(0, ge=0, le=5, description="Fetch up to N additional same-origin pages to widen detection")
    save_history: bool = Field(False, description="Append this scan to the local history DB for later timeline lookups")
    active_subdomains: bool = Field(False, description="Run subfinder for active subdomain enumeration (requires subfinder on PATH)")
    active_ports: bool = Field(False, description="Run naabu+nmap for real port/service scanning (requires naabu and/or nmap on PATH)")
    nuclei_scan: bool = Field(False, description="Auto-run nuclei vulnerability templates (requires nuclei on PATH)")
    nuclei_severity: Optional[str] = Field(None, description="Filter nuclei findings to one or more severities, e.g. 'high,critical'")
    harvest_urls: bool = Field(False, description="Collect historical + live URLs via gau, waybackurls, and katana")
    screenshot: bool = Field(False, description="Capture a screenshot via gowitness (requires gowitness + Chrome/Chromium)")
    screenshot_dir: str = Field("/tmp/inoue-screenshots", description="Directory to write gowitness screenshots to")


class BatchRequest(BaseModel):
    targets: list[str] = Field(..., min_length=1)
    timeout: int = Field(10, ge=1, le=120)
    follow_redirects: bool = True
    modules: Optional[list[str]] = None
    cve_min_severity: Optional[str] = None
    workers: int = Field(5, ge=1, le=50)
    rate_limit: Optional[float] = Field(None, gt=0, le=100)
    crawl_pages: int = Field(0, ge=0, le=5, description="Fetch up to N additional same-origin pages to widen detection")
    save_history: bool = Field(False, description="Append each scanned target to the local history DB")
    active_subdomains: bool = Field(False, description="Run subfinder for active subdomain enumeration per target (requires subfinder on PATH)")
    active_ports: bool = Field(False, description="Run naabu+nmap for real port/service scanning per target (requires naabu and/or nmap on PATH)")
    nuclei_scan: bool = Field(False, description="Auto-run nuclei vulnerability templates per target (requires nuclei on PATH)")
    nuclei_severity: Optional[str] = Field(None, description="Filter nuclei findings to one or more severities, e.g. 'high,critical'")
    harvest_urls: bool = Field(False, description="Collect historical + live URLs via gau, waybackurls, and katana per target")
    screenshot: bool = Field(False, description="Capture a screenshot per target via gowitness (requires gowitness + Chrome/Chromium)")
    screenshot_dir: str = Field("/tmp/inoue-screenshots", description="Directory to write gowitness screenshots to")


def validate_public_target(target: str, allow_private: bool = False) -> None:
    """Reject non-HTTP and private-network targets before an API scan."""
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=400, detail="Target must be an HTTP or HTTPS URL.")
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Target URLs may not contain credentials.")
    if allow_private:
        return
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Target hostname could not be resolved.")
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise HTTPException(status_code=403, detail="Private and non-public targets are disabled by the API.")


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

    serialize_result = serialize_scan_result
    allow_private_targets = os.getenv("INOUE_ALLOW_PRIVATE_TARGETS", "").lower() in {"1", "true", "yes"}

    async def scan_target(payload: ScanRequest):
        validate_public_target(payload.target, allow_private_targets)
        result = await asyncio.to_thread(
            scan,
            payload.target,
            timeout=payload.timeout,
            follow_redirects=payload.follow_redirects,
            modules=payload.modules,
            cve_min_severity=payload.cve_min_severity,
            allow_private_targets=allow_private_targets,
            crawl_pages=payload.crawl_pages,
            active_subdomains=payload.active_subdomains,
            active_ports=payload.active_ports,
            nuclei_scan=payload.nuclei_scan,
            nuclei_severity=payload.nuclei_severity,
            harvest_urls=payload.harvest_urls,
            screenshot=payload.screenshot,
            screenshot_dir=payload.screenshot_dir,
        )
        if payload.save_history and not result.error:
            from core.history import DEFAULT_HISTORY_PATH, record_snapshot
            from core.scanner import _serialize_scan_result
            await asyncio.to_thread(
                record_snapshot, DEFAULT_HISTORY_PATH, result.url, _serialize_scan_result(result)
            )
        return serialize_result(result)

    async def scan_batch(payload: BatchRequest):
        if len(payload.targets) > max_batch_size:
            raise HTTPException(status_code=400, detail=f"Batch size exceeds {max_batch_size}")
        for target in payload.targets:
            validate_public_target(target, allow_private_targets)
        results = await scan_many(
            payload.targets,
            timeout=payload.timeout,
            follow_redirects=payload.follow_redirects,
            modules=payload.modules,
            workers=payload.workers,
            rate_limit=payload.rate_limit,
            cve_min_severity=payload.cve_min_severity,
            allow_private_targets=allow_private_targets,
            crawl_pages=payload.crawl_pages,
            active_subdomains=payload.active_subdomains,
            active_ports=payload.active_ports,
            nuclei_scan=payload.nuclei_scan,
            nuclei_severity=payload.nuclei_severity,
            harvest_urls=payload.harvest_urls,
            screenshot=payload.screenshot,
            screenshot_dir=payload.screenshot_dir,
        )
        if payload.save_history:
            from core.history import DEFAULT_HISTORY_PATH, record_snapshot
            from core.scanner import _serialize_scan_result
            for item in results:
                if not item.error:
                    await asyncio.to_thread(
                        record_snapshot, DEFAULT_HISTORY_PATH, item.url, _serialize_scan_result(item)
                    )
        return {
            "results": [serialize_result(item) for item in results]
        }

    async def history(target: str, limit: int = 20):
        from core.history import DEFAULT_HISTORY_PATH, build_timeline, list_snapshots
        normalized = target if "://" in target else f"https://{target}"
        snapshots = await asyncio.to_thread(list_snapshots, DEFAULT_HISTORY_PATH, normalized, limit)
        timeline = await asyncio.to_thread(build_timeline, DEFAULT_HISTORY_PATH, normalized, limit)
        return {"target": normalized, "snapshots": len(snapshots), "timeline": timeline}

    app.get("/health")(health)
    app.get("/signatures")(signatures)
    app.post("/scan")(scan_target)
    app.post("/scan/batch")(scan_batch)
    app.get("/history/{target:path}")(history)
    for prefix in ("/api", "/api/v1"):
        app.get(f"{prefix}/health")(health)
        app.get(f"{prefix}/signatures")(signatures)
        app.post(f"{prefix}/scan")(scan_target)
        app.post(f"{prefix}/scan/batch")(scan_batch)
        app.get(f"{prefix}/history/{{target:path}}")(history)

    return app


app = create_app()
