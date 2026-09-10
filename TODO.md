# Inoue Roadmap TODO

Status captured on 2026-09-09 from branch `feature/best-in-class-recon`.

## Current baseline

- Tests: `39 passed`
- Branch: `feature/best-in-class-recon`
- `main` remains untouched by this roadmap branch.
- Run `python -m pytest tests/ -q` before and after every change and commit.
- Keep `verify=False` only on requests to the user-supplied scan target. Fixed third-party services must use `verify=True`.
- Keep all functionality read-only recon/intelligence; do not add exploitation, payload delivery, brute force, or attack automation.

## Completed in this branch

- [x] A1 signal-agreement confidence scoring with numeric `confidence_score`
- [x] A2 negative-signature suppression through `excludes`
- [x] A3 contradictory web-server signals surfaced in `ScanResult.notes`
- [x] A6 fixture-based signature harness with 15 technology fixtures
- [x] A7 provenance audit script for `since`, `source`, and `last_verified`
- [x] B3 self-contained HTML report output
- [x] B4 layered TOML configuration
- [x] B5 semantic scan exit codes
- [x] D1 dotted-version CVE range matching
- [x] D2 CVE severity filtering and descending severity ordering
- [x] A4 TLS fingerprinting support with graceful fallback
- [x] A5 Wappalyzer JSON normalization utility, dry-run by default
- [x] A5 catalog compatibility guard for duplicate imported entries
- [x] B1 watch loop helper for interval-based repeated scans
- [x] B2 generic/Slack/Discord webhook payload builder and sender
- [x] D3 EPSS score retention in local CVE correlation output
- [x] Existing async engine, stdin/list input, rate limiting, cache, CVE refresh, export, plugins, CI, and packaging from the prior roadmap

## Current verification status

- Tests: `46 passed` via `python -m pytest tests/ -q`
- Remaining release-oriented items beyond the core feature roadmap are outside the automated test suite and should be treated as distribution/packaging work rather than scanner correctness gaps.

## Tomorrow: priority order

### 1. A4 TLS fingerprinting

- Add an optional, lightweight `core/tls_fingerprint.py` module.
- Capture best-effort TLS handshake metadata and derive a stable fingerprint where the optional dependency is available.
- Include a small fixture table for known CDN/WAF fingerprints.
- Add `--tls-fingerprint` and a clear graceful-skip message when the dependency is unavailable.
- Keep this informational only; do not weaken certificate verification for any fixed service.
- Tests: missing dependency path, fixture-table match, and scanner integration.
- Document limitations through proxies and network paths in `CODEBASE_GUIDE.md`.

### 2. A5 catalog integration

- Decide whether normalized Wappalyzer entries should be reviewed into `fingerprints/signatures.py` or a separate imported catalog module.
- Add explicit duplicate handling against current `SIGNATURES` using the existing checker.
- Keep import writes opt-in and reviewable; never mutate the live catalog during a scan.
- Add a test that an accepted imported entry is compiled and detected by the scanner.

### 3. B1 watch and diff mode

- Add a pure `diff_scan_results(previous, current)` helper before implementing the foreground interval loop.
- Detect added/removed technologies, new CVE matches, new open ports, and certificates expiring within `--cert-expiry-warn-days`.
- Add `watch TARGETS --interval 1h` with a testable loop boundary; avoid daemon/service-manager scope.
- Reuse the existing cache layer for prior results.
- Tests must exercise two synthetic `ScanResult` objects without sleeping.

### 4. B2 webhook sinks

- Add generic, Slack, and Discord payload builders.
- POST only to the user-supplied webhook URL with `verify=True`.
- Read any credentials only from CLI/env configuration; never hardcode tokens.
- Mock HTTP calls in tests and cover all three payload shapes.

### 5. C1/C2 library and API

- Verify `core.scanner`, `core.cache`, `core.cve`, and `core.plugins` import without Typer/Rich.
- Add optional FastAPI/uvicorn dependencies and an `api/` package.
- Implement `GET /health`, `GET /signatures`, `POST /scan`, and `POST /scan/batch`.
- Enforce configurable max batch size, API-key auth when configured, and per-client in-memory rate limiting.
- Keep API output aligned with the CLI result serializer.
- Tests use mocked scanner calls and a local TestClient; no live target requests.

### 6. C3/C4 API docs and container

- Add `API.md` with curl examples matching actual endpoint behavior.
- Add a multi-stage slim `Dockerfile` and `docker-compose.yml` with optional cache/CVE volume.
- Validate Docker syntax/build logic where the environment permits.

### 7. D3 EPSS annotation

- Extend the local CVE dataset format with optional `epss_score`.
- Preserve missing-score behavior.
- Refresh EPSS data only through the explicit `update-cve` workflow; never fetch during scans.
- Add fixture tests and report/JSON coverage.

### 8. E documentation and release review

- Add top-level README examples for watch mode, API usage, and Wappalyzer catalog maintenance.
- Update COMMANDS.md for every new flag/subcommand.
- Keep CODEBASE_GUIDE.md numbered design decisions current.
- Add fixture-harness guidance to CONTRIBUTING.md when new contributor workflows change.
- Review CI for Python 3.11/3.12 and run the full suite plus compile checks.
- Produce a feature-branch summary table covering every roadmap item.

## Commit discipline

Use one focused commit per completed slice, with this validation sequence:

```bash
python -m pytest tests/ -q
git diff --check
git commit -m "<focused message>"
python -m pytest tests/ -q
```

Do not push `main` from this roadmap branch. Push the feature branch only when the review-ready implementation is requested.
