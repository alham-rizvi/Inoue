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

---

# Inoue Roadmap TODO - v2 (expanded, verification-first)

Status captured: 2026-09-10, building on branch `feature/best-in-class-recon`.

## Reconcile before doing anything else

The prior status doc lists A4, A5, B1, B2, and D3 as both completed and pending. Resolve that contradiction before adding new feature work.

- [ ] Audit the actual diff and commits on `feature/best-in-class-recon` for A4, A5, B1, B2, and D3.
- [ ] Rewrite pending entries to describe only missing hardening or verification work.
- [ ] Investigate any completed checkbox without a corresponding implementation commit.
- [ ] Run `git log --oneline feature/best-in-class-recon` and cross-check every completed item against a commit.
- [ ] Make the Completed and Tomorrow sections mutually exclusive and accurate.

## Verification checklist

- [ ] Run `python -m pytest tests/ -q --collect-only` and confirm the expected test count.
- [ ] Run `python -m pytest tests/ -rs` and review skips.
- [ ] Search tests for swallowed exceptions and vacuous assertions: `except Exception: pass` and `assert True`.
- [ ] Manually exercise A1 confidence scoring against multiple real sites and confirm differentiated scores.
- [ ] Exercise A2 generic/specific suppression with a constructed signal pair.
- [ ] Confirm A3 contradiction notes do not appear on ordinary scans.
- [ ] Run the fixture harness and perform a mutation spot-check for A6.
- [ ] Run the A7 provenance audit and review stale-signature output.
- [ ] Generate and open a B3 HTML report in a browser.
- [ ] Verify B4 CLI, project config, user config, and built-in precedence in both directions.
- [ ] Verify B5 shell exit codes for success, scan error, and fail-on-CVE scenarios.
- [ ] Test D1 with messy versions such as `2.4.52-ubuntu`, `v1.2`, and `1.2.3+build4`.
- [ ] Confirm D2 filtering retains critical findings when filtering at medium severity.
- [ ] Record which checks pass, reveal real bugs, or reveal test-only bugs.
- [ ] Block new subsystem work when its prerequisite verification reveals a real bug.

## Dead-end and technical-debt sweep

- [ ] Triage `TODO`, `FIXME`, and `XXX` comments in `core/`, `inoue.py`, and `api/`.
- [ ] Search for orphaned code, unused imports, and half-wired plugin or cache paths.
- [ ] Compare every CLI flag from `python inoue.py --help` with `COMMANDS.md`.
- [ ] Confirm each subsystem has tests that exercise real code paths: cache, CVE, plugins, TLS, and API.
- [ ] Run `python -m pytest tests/ -q -W error` and resolve dependency deprecation warnings.

## Eight-week execution plan

### Week 1 - Reconciliation and verification

- [ ] Complete the reconciliation and verification checklists above.
- [ ] Fix real bugs and incorrect test assertions found during the audit.
- [ ] Update `CODEBASE_GUIDE.md` and add a three-line status entry to the log below.

### Week 2 - A4 TLS fingerprinting hardening

- [ ] Capture reproducible fixtures for Cloudflare, Akamai, Fastly, and CloudFront where network access permits.
- [ ] Test dependency-missing, known-match, and unknown-fingerprint paths.
- [ ] Document proxy and TLS-terminating load-balancer limitations in `CODEBASE_GUIDE.md`.

### Week 3 - A5 catalog integration and B1 diff helper

- [ ] Complete the Wappalyzer workflow: dry-run diff, human review, explicit apply, deduplication, compilation, and detection test.
- [ ] Test technology additions, removals, version changes, new and resolved CVEs, port changes, and certificate states.
- [ ] Decide and document which changes are actionable notifications.

### Week 4 - B1 watch loop and B2 webhooks

- [ ] Wire the watch loop to the diff helper with a bounded foreground execution model.
- [ ] Manually validate a webhook payload against a throwaway endpoint without committing credentials.
- [ ] Keep daemon and service-manager integration out of scope.

### Week 5 - C1 library and C2 API foundation

- [ ] Import core modules in an environment without Typer or Rich installed.
- [ ] Validate `/health`, `/signatures`, and `/scan` using mocked scanner calls.
- [ ] Document API-key authentication and in-memory rate-limit limitations.

### Week 6 - C2 batch, C3 docs, and C4 Docker

- [ ] Enforce and test the API batch maximum.
- [ ] Run every `API.md` curl example against a local server.
- [ ] Run `docker build` when Docker is available, otherwise record the limitation explicitly.

### Week 7 - D3 EPSS and CVE hardening

- [ ] Keep EPSS refresh restricted to the explicit `update-cve` workflow.
- [ ] Revisit messy-version and severity-filter behavior.
- [ ] Add a CVE dataset staleness warning if the product policy supports it.

### Week 8 - Documentation and release review

- [ ] Update README, COMMANDS.md, CONTRIBUTING.md, and CODEBASE_GUIDE.md.
- [ ] Perform a fresh-clone install and end-to-end CLI run against several safe targets.
- [ ] Exercise JSON, HTML, cache, CVE, watch, API, and Docker workflows where available.
- [ ] Produce a feature summary table with implementation and hands-on verification status.
- [ ] Decide go/no-go for the next release and list blockers if not ready.

## Monthly maintenance cadence

- [ ] Week 1: audit signatures with `scripts/audit_signatures.py --stale-days 90`.
- [ ] Week 2: refresh the CVE dataset and review TLS fixture drift.
- [ ] Week 3: triage catalog contributions using the fixture harness.
- [ ] Week 4: update dependencies, run the full suite with `-W error`, and review security advisories.

## Commit discipline

```bash
python -m pytest tests/ -q
git diff --check
git commit -m "<focused message>"
python -m pytest tests/ -q
```

Never mark a checkbox complete without a corresponding commit hash. Add the short hash beside completed items, for example:

```markdown
- [x] A1 signal-agreement confidence scoring (`a1b2c3d`)
```

## Roadmap v2 log

- 2026-09-10: Added the verification-first reconciliation plan after detecting conflicting completed and pending status entries.
- 2026-09-10: Added a curated web-server dataset with 63 server-family entries; full suite passed with 48 tests and the duplicate-signature checker passed.
