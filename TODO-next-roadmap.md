# Inoue — Next Implementation Roadmap

Snapshot of what's actually built as of this session, and what's genuinely
still missing. Written after auditing the real codebase (not from memory) so
this doesn't re-propose things that already exist.

## Already shipped (do not re-implement)

Fingerprinting: ~21,000 signatures, aggressive version detection with
provenance labeling, JS bundle re-fingerprinting, favicon hashing.
Records: extended DNS (CAA/SOA/SRV/DNSSEC/PTR), domain + IP/ASN WHOIS.
Web posture: WAF/CDN detection, security header grading, CORS
misconfiguration, cookie flag audit, CSP weakness parsing, redirect chain
analysis, HTTP method enumeration. Email posture: SPF/DMARC/DKIM/MTA-STS.
Recon: sitemap+katana crawl, subdomain takeover fingerprinting, API
surface discovery (OpenAPI/Swagger + GraphQL introspection), technology
EOL detection, external tool orchestration (subfinder/naabu/nmap/nuclei/
gau/waybackurls/katana/gowitness). Scoring: triage risk score combining
every signal above. Interfaces: CLI, FastAPI backend, browser extension,
7-tool MCP server (dual SDK, multi-transport). History: append-only scan
snapshots with timeline diffing.

---

## Phase 0 — Scope guardrails (still not built; do this first)

This was flagged as priority zero in the original roadmap and never got
built, while a lot of heavier active-recon capability (external tools,
takeover checks, API probing) got added on top of it. That's backwards —
every one of those makes more requests per target, with nothing yet
stopping a scan from wandering out of a program's declared scope.

- [ ] `--scope scope.yaml` — explicit in-scope/out-of-scope domains and
      CIDR ranges. Every module that fires a request (crawl, external
      tools, takeover, API discovery) checks it before firing.
- [ ] `scope init <program-url>` — fetch a public program's scope page
      (HackerOne/Bugcrowd JSON API where available) into a starter file.
- [ ] Global request budget per target (`--max-requests N`).
- [ ] `--respect-robots` (on by default for crawl mode) — parse
      `robots.txt` `Disallow` and skip those paths rather than only
      checking whether the file exists (current directory-enum code
      checks for `/robots.txt` presence but never parses it).

## Phase 1 — Close the remaining detection gaps

- [ ] **Headless rendering fallback** (`--render`, Playwright, opt-in).
      The JS-intel module analyzes bundle *text*; it still can't see
      what a page looks like after JS actually executes. Trigger
      automatically when static + JS-bundle detection both return
      near-zero technologies.
- [ ] **robots.txt intelligence** — parse `Disallow` entries and surface
      the interesting ones (admin/backup/config paths) as a recon
      signal, independent of whether `--respect-robots` is also crawling
      them.
- [ ] **Cloud storage bucket enumeration** — permutate the target's
      name/subdomains against S3/GCS/Azure Blob naming conventions,
      check existence + public-listing status via a plain GET. Different
      from the existing takeover check: this looks for buckets that
      exist and are misconfigured, not ones that are unclaimed.
- [ ] **TLS/cipher weakness flagging** — `core/tls_fingerprint.py`
      already captures the negotiated protocol/cipher; nothing yet
      flags TLSv1.0/1.1 or weak cipher suites as a risk factor the way
      `core/security_grade.py` does for headers.
- [ ] **Mixed content / Subresource Integrity (SRI)** — an HTTPS page
      loading `http://` resources, or a cross-origin `<script>`/`<link>`
      without an `integrity` attribute (supply-chain risk). Natural fit
      alongside the existing CSP analysis in `core/http_posture.py`.

## Phase 2 — Make the triage score actually usable across many targets

`core/risk.py` already has `rank_results()`, but nothing in the CLI
surfaces it — right now you'd have to script it yourself.

- [ ] `inoue triage <scope-file-or-target-list>` — run `scan_many`
      across a list, then print `rank_results()` output as one ordered
      table instead of N separate reports. This is the actual bug-bounty
      workflow: 200 subdomains, limited time, which 5 do you open first.
- [ ] Auto-screenshot (gowitness) only for targets that land in the
      `investigate-first`/`worth-a-look` bands, instead of an all-or-
      nothing `--screenshot` flag — keeps the expensive step bounded to
      what's actually worth a human glance.
- [ ] Nuclei template selection aware of detected WAF — skip templates
      known to trip easy blocks unless `--force`.

## Phase 3 — Scheduled/continuous recon

`core/webhooks.py` already builds Slack/Discord/generic payloads and
`core/history.py` already diffs snapshots — the missing piece is what
connects them over time.

- [ ] `inoue watch <target> --interval 24h` — periodic re-scan,
      `--save-history` automatically, diff against the last snapshot,
      fire a webhook only when the diff is non-empty (new tech, new CVE,
      cert nearing expiry, risk band changed).
- [ ] Certificate-expiry-specific alerting — the diff already reports
      `certificate_expiry` entries; wire that straight to webhooks
      without waiting for a full re-scan cycle to notice.

## Phase 4 — Catalog and quality debt (ongoing, not a one-time task)

- [ ] Continue tightening HTML-token-only signatures for precision (the
      false-positive class already found and partially fixed this
      session — this is recurring maintenance, not a single PR).
      Expand the favicon and EOL tables incrementally, each entry
      individually verified and cited, same discipline used for the
      current three EOL-covered runtimes.
- [ ] Benchmark scan time as more modules stack up (`--full-recon` +
      external tools + JS intel + API discovery all together) and keep
      `--fast` genuinely fast — it should still skip all of the above by
      default.

---

## Suggested order

1. Phase 0 scope guardrails — everything after this fires more requests.
2. Phase 2's `inoue triage` command — smallest amount of new code for
   the highest day-to-day workflow improvement, since the scoring logic
   already exists.
3. Phase 1's TLS weakness + mixed-content/SRI checks — cheap, same
   pattern as existing posture checks, no new dependencies.
4. Phase 1's robots.txt intelligence + bucket enumeration.
5. Phase 3 scheduled watch mode — biggest effort, do once the above is
   solid, since it depends on Phase 0 scope-safety being in place first.
6. Phase 1 headless rendering — highest effort of everything here
   (heavy dependency, browser binary management), save for last.
