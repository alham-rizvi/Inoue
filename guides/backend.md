# Backend architecture and API details

## Overview

The backend is built around the same scanner core used by the CLI. The FastAPI application in `api/main.py` does not duplicate detection logic; it validates inputs, enforces read-only safety controls, and delegates work to the canonical scan functions in `core/scanner.py`.

## Request flow

The standard request lifecycle is:

1. API receives a POST body for `/scan` or `/scan/batch`.
2. Pydantic validates timeout, batch size, workers, and other bounds.
3. `validate_public_target()` confirms the target is an HTTP(S) URL, has no embedded credentials, and resolves to a public address unless the environment explicitly allows private targets.
4. The request is executed in a worker thread for single-scan requests to avoid blocking the async event loop.
5. The scanner runs and returns a result object that is serialized using the project’s standard serializer.
6. JSON is returned to the caller with the same top-level structure used elsewhere in the project.

## Security features

The API includes several safety checks:

- Only `http` and `https` schemes are accepted.
- Credentials in URLs are rejected.
- Private, loopback, link-local, reserved, and unresolved hosts are blocked by default.
- Redirects are revalidated if the service is operating in public-target mode.
- Optional API key enforcement can be enabled through `INOUE_API_KEY`.
- Rate limits can be configured with `INOUE_API_RATE_LIMIT`.
- Maximum batch sizes are controlled via `INOUE_API_MAX_BATCH_SIZE`.

This design keeps the API aligned with the project’s recon-only and read-only scope.

## Exposed endpoints

### `GET /health`
Returns a minimal health response and is mirrored under `/api/health` and `/api/v1/health`.

### `GET /signatures`
Returns the signature catalog count and a short preview of the available signatures.

### `POST /scan`
Accepts a single target and optional scan settings such as timeout, redirect behavior, modules, and CVE severity threshold.

### `POST /scan/batch`
Accepts a list of targets with batch scaling controls and returns a list of serialized scan results.

## Scan configuration model

The same scanner supports both synchronous CLI runs and async API requests. The request schema intentionally exposes a narrow set of operational controls rather than arbitrary internal flags. That keeps the backend stable while still allowing the CLI and API to request the same underlying scan behavior.

## Result contract

API responses use the same serialized result contract as the CLI and export system, ensuring downstream tooling does not need an API-specific schema. In practice this means the backend returns fields for:

- URL and target identity
- Technologies and confidence values
- Headers and response metadata
- DNS, SSL, WHOIS, mail, and subdomain results
- Port and service hints
- CVE matches and notes
- Plugin output and enrichment data
- Cache status and error entries

## Async and threading choices

Single-target scans are executed in an executor thread using `asyncio.to_thread`, which keeps the event loop responsive while still reusing the synchronous scanner logic. Batch operations use the scanner’s async helper flow and can still honor worker counts, rate limiting, and selected modules.

## Extension integration

The browser extension calls the local API with the `fast` module preset. This means extension-based detection stays consistent with the CLI and API output without re-implementing matching logic in JavaScript.

## Operational guidance

For local development:

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health
```

For API-protected deployments, set the API key and pass it as the `X-API-Key` header. For isolated lab testing, set `INOUE_ALLOW_PRIVATE_TARGETS=true` only in a controlled environment.

## Failure handling

The scanner and API are designed to keep single failures isolated rather than taking down a full scan. Optional module errors become fields in the output instead of breaking the complete result. This is especially important for optional recon sources such as WHOIS, SSL details, or public-intelligence fetches.
