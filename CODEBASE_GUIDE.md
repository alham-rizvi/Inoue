# Codebase Guide

This repository is a compact recon and fingerprinting tool focused on identifying the stack behind a public website or service. It is intentionally small enough for a single engineer or agent to understand in one pass, but the scanner logic and signature catalog are dense enough that architecture context matters.

## Project purpose

Inoue is designed to answer a practical question quickly:

- What technologies is this target exposing?
- Which framework, CMS, app server, UI library, or admin panel is visible?
- Are there API routes, login surfaces, or management portals that hint at the platform?
- What version information can be inferred from headers, HTML, script URLs, and path patterns?

This is a recon and surface-analysis tool, not a privileged exploitation framework. It prioritizes safe, read-only observation of public-facing endpoints.

## Repository layout

- `inoue.py` — CLI entry point, argument parsing, multi-target execution, and update flow
- `core/scanner.py` — main detection engine, recon orchestration, and network helpers
- `core/cache.py` — opt-in SQLite cache for repeat scan results
- `core/cve.py` — offline CVE dataset loading and exact version correlation
- `core/plugins.py` — optional result-plugin discovery and error isolation
- `data/cves.json` — bundled CVE awareness dataset
- `modules/example_plugin.py.template` — plugin interface template
- `scripts/check_signatures.py` — duplicate signature key checker and merger
- `fingerprints/signatures.py` — the primary matching catalog for technologies and services
- `fingerprints/extended_catalog.py` — supplementary scan catalog and extended platform entries
- `tests/test_scanner.py` — regression tests for detection correctness and CLI contracts
- `README.md` — public project overview and usage examples
- `GUIDE.md` — catalog extension and version-detection guidance
- `COMMANDS.md` — CLI command reference
- `SECURITY.md` — supported versions and valid security reporting policy

## Critical design decisions

### 1. Detection is multi-signal and score-based

The scanner matches a candidate technology against multiple data sources:

- HTTP headers
- cookies
- HTML body content
- script tag sources
- meta tag values
- URL paths and known login/admin routes

Each signal contributes a confidence ranking. A signature that matches a strong header like `Server: nginx/1.26.1` is considered more reliable than a loose HTML snippet or a generic path hit. The engine prefers the most specific evidence while still allowing broader heuristic matches.

### 2. Candidate filtering is intentionally aggressive

The project avoids checking every technology signature against every response. Instead, it builds a candidate set from tokens present in the response. This keeps the scanner fast and prevents surprising false matches when the body is sparse or highly generic.

The key implementation is in `run_fingerprints()` and the candidate-building helpers in `core/scanner.py`.

### 3. Version detection favors explicit capture groups

When adding a new signature, use regexes that capture version-like content directly. The helper `_extract_version()` tries to normalize values like:

- `1.2.3`
- `v1.2.3`
- `release-2.4`
- `Version: 3.0.1`

If a regex has a capture group, prefer that over fuzzy extraction from a large HTML block.

### 4. Path-aware detection is important

A lot of recon value comes from route names such as:

- `/graphql`
- `/wp-admin`
- `/phpmyadmin`
- `/swagger-ui`
- `/openapi.json`
- `/grafana`
- `/jenkins`

These route matches are intentionally part of the detection flow even when the response is otherwise generic.

### 5. The CLI is the public contract

The `inoue.py` entry point is the interface users and other tools see. Changes there should preserve:

- CLI option names and defaults
- JSON output shape
- result rendering stability for repeated scans
- minimal risk of breaking `python inoue.py <target>` usage

The scanner core and the CLI are intentionally separate. The CLI is not meant to grow broad orchestration logic beyond user-facing dispatch.

### 6. Async batches share one HTTP client

`scan_many()` uses `httpx.AsyncClient` and `asyncio.gather()` with a bounded semaphore. The older `scan()` function remains synchronous for compatibility. The CLI uses the async path when `--rate-limit` or `--cache` is enabled.

### 7. Caching is opt-in

`--cache` stores serialized scan results in `~/.cache/inoue/cache.db` by default. `--cache-path` and `--cache-ttl` control storage and freshness. Cache hits are reported through progress output; without `--cache`, no cache database is opened.

### 8. CVE correlation is local and informational

`--cve` compares exact `(technology, version)` pairs against `data/cves.json`. It does not call a live API during scans and never retrieves or executes exploits. `python inoue.py update-cve` is the explicit refresh path; it downloads an NVD 2.0 JSON feed with verified TLS and converts it into the local dataset.

### 9. Plugin output is enrichment only

Plugins are Python files with a `run(result)` function in `modules/` or `~/.config/inoue/modules/`. Their return values are placed under `result.enriched["plugins"]`. Plugin exceptions become an error entry and do not fail the scan. Use `--plugin-dir` for an additional directory.

### 10. Nuclei export format

`--nuclei-out FILE` writes a JSON mapping from normalized technology tags to deduplicated final URLs, such as `{"apache": ["https://example.com"]}`.

## How a scan executes

The flow is roughly:

1. CLI resolves user flags and target list.
2. `scan()` normalizes the target into a URL and hostname.
3. A request is sent via `httpx` with TLS verification disabled for the scanned target only.
4. Response headers, cookies, and body are extracted.
5. `run_fingerprints()` filters candidates and matches known signatures.
6. Recon modules may run in parallel for DNS, SSL, WHOIS, subdomains, directories, and public intel.
7. `ScanResult` is returned and rendered or serialized.

## Known gotchas and safety notes

### `verify=False` is only for the scanned target

This project deliberately disables certificate verification only in outbound requests to the target under investigation. It should not be used broadly for arbitrary endpoints or for unreviewed third-party requests.

### Keep signature changes boring and testable

The most common regression risk is broad matching logic changing unexpectedly. Prefer targeted signatures and targeted tests over large regex rewrites.

### Avoid dangerous or exploitative behaviors

The project is intentionally recon-focused. It should not add functionality whose primary purpose is exploitation, credential abuse, or automated attack behavior against a host.

### Threaded recon should remain bounded

The scan pipeline uses a limited thread pool for DNS, SSL, and other tasks. Keep worker counts bounded and avoid introducing unbounded network fan-out.

## Working on the codebase

When making changes, follow this order:

1. Read affected files and tests.
2. Add or update a focused failing test.
3. Fix the root cause in the minimal file(s).
4. Run the relevant tests and the project suite.
5. Keep edits small and reviewable.

## Recommended first reads when making a change

- `core/scanner.py` for scan orchestration and matching logic
- `fingerprints/signatures.py` for technology catalog entries
- `tests/test_scanner.py` for expected behavior and regression coverage
- `inoue.py` for CLI contract compatibility

## Roadmap context

The repository is moving toward a more pipeline-friendly and community-scalable recon tool. The planned evolution includes:

- async multi-target scanning
- better concurrency and rate control
- mass-target input handling
- caching and deduplication
- richer CVE and vulnerability correlation
- export formats such as Nuclei-friendly output
- plugin architecture for recon modules
- CI and release hygiene
- signature catalog normalization and deduplication

The implementation should remain focused on recon and intelligence gathering while keeping the tool easy to reason about and test.

## Packaging and catalog maintenance

The project is installable with `pip install .` and exposes the `inoue` console command. Build artifacts locally with `python -m build` after installing the `build` package. Publishing is intentionally manual and requires an authorized maintainer review.

The catalog checker can merge legacy duplicate definitions once with `python scripts/check_signatures.py --rewrite`; CI runs `python scripts/check_signatures.py` without rewriting.
