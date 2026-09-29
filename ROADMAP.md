# Inoue Roadmap

Single source of truth for what is built and what is still open. This file
replaces the former `TODO.md`, `TODO-next-roadmap.md` and
`TODO-bugbounty-roadmap.md` (and the Roadmap section of `SUMMARY.md`), which
had drifted into listing the same items as both "completed" and "next
priority".

Every status below was checked against the codebase on 2026-09-29 rather than
copied from the older docs. Items are only listed as shipped when there is a
module/flag to point at; everything else is under **Still open**. The
historical bug write-ups stay in [guides/Bugs-to-fix.md](guides/Bugs-to-fix.md)
and are linked from here rather than duplicated.

## Ground rules (non-negotiable)

- Everything stays **read-only recon**. No exploitation, no brute force, no
  payload delivery, no active attack automation - bug bounty programs revoke
  access for anything beyond passive/light-active recon.
- `verify=False` is allowed only on requests to the user-supplied scan target.
  Fixed third-party services (CT logs, CVE feeds, webhook sinks) keep
  `verify=True`.
- Every change ships with tests: run `python -m pytest tests/ -q` before and
  after it.
- New network calls must respect `allow_private_targets`, rate limiting, and
  (where provided) the scope file - no exceptions.
- One focused commit per slice; never mark an item done without a commit hash.

## Shipped (verified against the code)

| Area | Where it lives |
|---|---|
| Scope file with wildcard/CIDR matching and fail-closed behaviour | `core/scope.py` (`Scope`, `parse_scope_file`, `filter_hosts`), `--scope` |
| WAF/CDN detection | `core/waf.py`, `result.waf`, CLI "WAF / CDN" section |
| JavaScript harvesting and intel | `core/js_intel.py`, `--js-intel`, secrets redacted |
| Subdomain takeover fingerprinting | `core/takeover.py`, `--check-takeover` |
| API surface discovery | `core/api_discovery.py`, `--api-discovery` |
| Security-header / CORS grading | `core/security_grade.py`, `core/http_posture.py` |
| Crawl expansion including `sitemap.xml` | `--crawl`, `--crawl-katana` |
| Hydration payload parsing and JS-global markers | signature schema + `core/scanner.py` |
| Nuclei export | `write_nuclei_export` (`--export-nuclei`) |
| Multi-target ranking helper | `core/risk.py` `rank_results` (library only - no CLI yet) |
| TLS fingerprinting | `--tls-fingerprint`, `core/tls_fingerprint.py` |
| EPSS score retention | `core/cve.py` |
| FastAPI backend | `api/main.py` |
| MCP server | `mcp_server.py` |
| Scan history / timeline | `inoue history`, `core/history.py` |
| Watch mode | `inoue watch` (commit `62fd3c2`) |
| Webhook delivery (generic/Slack/Discord) | `--webhook-url`, `--webhook-format` (commit `13ac7f7`) |

Ongoing per-area work is listed under **Still open** even when the surrounding
feature shipped - a shipped detector is not the same as a finished catalog.

## Still open

### Guardrails

- [ ] Global request budget per target (`--max-requests N`) so a single
      `--full-recon --crawl 20` run cannot accidentally hammer a target; most
      programs specify a rate limit in their policy.
- [ ] `--respect-robots` (on by default for crawl mode). `core/scanner.py`
      currently only checks whether `/robots.txt` exists - it never parses
      `Disallow`, so crawling still visits paths programs asked bots to avoid.
- [ ] `scope init <program-url>` - fetch a public program's scope page
      (HackerOne/Bugcrowd JSON API where available) into a starter scope file.
      The scope *matcher* shipped; this importer did not.

### Detection gaps

- [ ] **robots.txt intelligence** - parse `Disallow` entries and surface the
      interesting ones (admin/backup/config paths) as a recon signal,
      independent of whether `--respect-robots` is also crawling them.
- [ ] **Cloud storage bucket enumeration** - permutate the target's
      name/subdomains against S3/GCS/Azure Blob naming conventions and check
      existence + public-listing status via a plain GET. Different from the
      shipped takeover check: this looks for buckets that exist and are
      misconfigured, not ones that are unclaimed.
- [ ] **TLS/cipher weakness flagging** - `core/tls_fingerprint.py` already
      captures the negotiated protocol/cipher; nothing yet flags TLSv1.0/1.1 or
      weak cipher suites as a risk factor the way `core/security_grade.py`
      does for headers.
- [ ] **Mixed content / Subresource Integrity (SRI)** - an HTTPS page loading
      `http://` resources, or a cross-origin `<script>`/`<link>` without an
      `integrity` attribute (supply-chain risk). Natural fit next to the
      existing CSP analysis in `core/http_posture.py`.
- [ ] **Headless rendering fallback** (`--render`, Playwright, opt-in). The
      JS-intel module analyzes bundle *text*; it still cannot see what a page
      looks like after JS executes. Trigger automatically when static +
      JS-bundle detection both return near-zero technologies. Must degrade
      gracefully - the tool has to work identically without Playwright, just
      with reduced SPA coverage (same pattern as the TLS optional dependency).
- [ ] **Parameter mining** (`--export-params`) - collect candidate parameter
      names from JS, forms and crawled URLs into a per-target wordlist. Does
      not test anything; hands off to ffuf/Arjun, keeping Inoue in "recon".
- [ ] **Expanded sensitive-file sweep** - extend `_enumerate_directories`
      beyond the current small guess list with a curated (not brute-force) set
      of near-universal exposure paths: `.env`, `.git/config`, `.git/HEAD`,
      `.DS_Store`, `docker-compose.yml`, `.aws/credentials`, backup patterns
      (`.bak`, `~`, `.old`). Keep it bounded and rate-limited.

### Triage and workflow

- [ ] `inoue triage <scope-file-or-target-list>` - run `scan_many` across a
      list and print `rank_results()` as one ordered table instead of N
      reports. The scoring logic already exists; only the CLI surface is
      missing. This is the actual bug-bounty workflow: 200 subdomains, limited
      time, which 5 do you open first.
- [ ] Auto-screenshot (gowitness) only for targets in the
      `investigate-first`/`worth-a-look` bands, instead of the all-or-nothing
      `--screenshot` flag, so the expensive step stays bounded.

### Output and tool-chain integration

- [ ] WAF-aware nuclei templates - skip templates known to trip easy blocks
      when a WAF was detected, unless `--force`.
- [ ] `--export-amass` / `--export-subfinder`-style subdomain list export
      (subdomain discovery already exists; only the output adapter is
      missing).
- [ ] Add WAF, JS-intel and takeover candidates as report sections in the
      existing Markdown/HTML renderer (additive).

### Catalog quality and scale (ongoing, never "done")

- [ ] Continue tightening HTML-token-only signatures for precision. Generic
      HTML substrings still produce false positives (the class captured in
      [guides/Bugs-to-fix.md](guides/Bugs-to-fix.md) P1-1); anything flagged
      as a specific commercial product should require header/meta
      corroboration rather than an HTML-token-only match.
- [ ] `--strict` mode raising the minimum confidence score required to report
      a detection - more useful as WAF/JS-intel feed more candidate text into
      the matcher.
- [ ] Expand the favicon and WAF-block-page catalogs incrementally with
      `scripts/collect_favicon_hash.py`, each entry individually verified and
      cited, never as a batch import.
- [ ] Benchmark scan time as modules stack up and keep `--fast` genuinely
      fast - it should still skip the heavy phases by default.

### Light-active WAF probing

- [ ] `--waf-probe` - send a single benign-but-unusual high-entropy path
      (e.g. `/inoue-waf-probe-<random>`) and fingerprint the **block page** if
      one comes back. This is the single highest-signal WAF check that exists,
      but it is one non-organic request, so it stays opt-in behind a flag.
      Never send anything that looks like an attack payload (no `' OR 1=1`, no
      `<script>`, no path traversal) - a benign unusual path is enough to trip
      most rulesets and keeps this in "recon" rather than "testing the WAF".

## Suggested order

1. Guardrails first: `--max-requests`, then `--respect-robots` parsing - every
   other item below fires more requests per target.
2. `inoue triage` - smallest amount of new code for the biggest day-to-day
   workflow win, because the scoring logic already exists.
3. TLS weakness + mixed-content/SRI checks - cheap, same pattern as the
   existing posture checks, no new dependencies.
4. robots.txt intelligence + bucket enumeration.
5. `--waf-probe`, WAF-aware nuclei templates, subdomain export adapters.
6. Scheduled watch/certificate alerting refinements (already partly shipped
   via `inoue watch` + `--webhook-url`).
7. Headless rendering - highest effort of everything here (heavy dependency,
   browser binary management), so it goes last.

## Maintenance cadence

- Week 1: audit signatures with `scripts/audit_signatures.py --stale-days 90`.
- Week 2: refresh the CVE dataset and review TLS fixture drift.
- Week 3: triage catalog contributions using the fixture harness.
- Week 4: update dependencies, run the full suite with `-W error`, review
  security advisories.

## History

- The three former TODO files each carried their own "already shipped" and
  "next" lists; several items (WAF detection, JS intel, takeover checks, API
  discovery, security grading, TLS fingerprinting, EPSS, API/MCP/history,
  watch mode, webhooks) appeared in both, which made the docs unusable as a
  status source. Those are now listed once, under **Shipped**.
- Per-commit evidence for the completed bug sweep is kept in
  [guides/Bugs-to-fix.md](guides/Bugs-to-fix.md).
