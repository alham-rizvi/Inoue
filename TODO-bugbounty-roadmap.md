# Inoue → Bug Bounty Recon Platform: Roadmap

Goal: extend Inoue from a Wappalyzer/BuiltWith-style tech fingerprinter into a
recon tool that's actually useful during a bug bounty engagement — WAF-aware,
JS-aware, and safe to point at real scope.

Ground rules (carried over from the existing TODO.md, non-negotiable):
- Everything stays **read-only recon**. No exploitation, no brute force,
  no payload delivery, no active attack automation. Bug bounty programs
  revoke access and can report you for anything beyond passive/light-active recon.
- `verify=False` is allowed only on requests to the user-supplied scan
  target. Third-party services (CT logs, CVE feeds, webhook sinks) keep
  `verify=True`.
- Every phase ships with tests. Run `python -m pytest tests/ -q` before
  and after every change.
- New network calls must respect `allow_private_targets`, rate limiting,
  and (new, see Phase 0) the scope file — no exceptions.

---

## Phase 0 — Scope & safety guardrails (do this first, before anything else)

This is the phase most people skip and the one that gets your bug bounty
account banned. Build it before you build anything that makes more
requests per target.

- [ ] `--scope scope.yaml` — explicit in-scope/out-of-scope domain and
      IP-range list (most programs publish this exact format). Every
      module (crawl, subdomains, ports, directory enum) must check scope
      before firing a single request, not after.
- [ ] Out-of-scope wildcard and CIDR matching (`*.internal.example.com`,
      `10.0.0.0/8` exclusions are common).
- [ ] Global request budget per target (`--max-requests N`) so a single
      `inoue scan --full-recon --crawl 20` run can't accidentally hammer
      a target — most programs specify a rate limit in their policy.
- [ ] `--respect-robots` flag (on by default for crawl mode) so you're
      not scraping paths programs have explicitly asked bots to avoid.
- [ ] A `scope init <program-url>` helper that fetches a program's public
      scope page (HackerOne/Bugcrowd JSON API where available) and writes
      a starter `scope.yaml` — huge quality-of-life win, low effort.
- [ ] Tests: scope matcher unit tests (wildcard, CIDR, explicit deny
      overriding allow), and an integration test proving a module refuses
      to fire on an out-of-scope host.

---

## Phase 1 — WAF / CDN detection (the thing you specifically asked for)

You already have `core/tls_fingerprint.py` (TLS handshake metadata) and a
`fingerprints/web_server_catalog.py` — this phase adds a dedicated
detection layer instead of hoping generic signatures catch it.

- [ ] New `core/waf.py` module with a dedicated `WAFDetection` type
      (name, vendor, confidence, evidence) — separate from `Detection`
      because WAF detection uses different signals (block-page fingerprints,
      not header/script/meta matches) and callers should be able to
      distinguish "this is your stack" from "this is what's in front of it".
- [ ] Passive signals (always safe, zero extra requests):
  - [ ] Header fingerprints: `cf-ray`/`cf-cache-status` (Cloudflare),
        `x-sucuri-id`, `x-akamai-*`, `x-cdn`, `server: cloudfront`,
        `x-iinfo` (Incapsula), `x-distil-cs` (Distil), `x-fw-hash`.
  - [ ] Cookie fingerprints: `__cfduid`/`cf_clearance`, `incap_ses_*`,
        `visid_incap_*`, `AWSALB`/`AWSALBCORS`.
  - [ ] TLS/JA3-style fingerprint correlation with known CDN edge nodes
        (extends `core/tls_fingerprint.py`).
- [ ] Light-active signal (opt-in, one extra request, still read-only):
  - [ ] Send a single high-entropy/benign-but-unusual path
        (e.g. `/inoue-waf-probe-<random>`) and fingerprint the **block
        page** if one comes back (WAFs have very distinctive 403/406
        error pages — this is exactly what wafw00f does, and it's the
        single highest-signal WAF check that exists). Gate behind
        `--waf-probe` since it's one non-organic request.
  - [ ] Never send anything that looks like an actual attack payload
        (no `' OR 1=1`, no `<script>`, no path traversal) — a *benign*
        unusual path is enough to trigger most WAF rulesets and keeps
        this squarely in "recon" rather than "testing the WAF's rules".
- [ ] Seed catalog for the ~15 WAFs/CDNs that cover the vast majority of
      real-world traffic: Cloudflare, Akamai, AWS CloudFront/WAF,
      Imperva/Incapsula, Sucuri, F5 BIG-IP ASM, Fastly, StackPath,
      Azure Front Door/WAF, Barracuda, Fortinet FortiWeb, DenyAll,
      Wallarm, Distil Networks, Radware AppWall.
  - Same honesty rule as the favicon catalog: only ship signatures
    you've verified, cite the source, and don't guess header values.
- [ ] Wire into `--waf` module flag, `run_fingerprints`-style plan gating
      (so `--dns` still doesn't trigger it — don't repeat that bug),
      and both CLI/API output.
- [ ] Tests: one fixture per catalog entry (mocked headers/cookies/block
      page), a negative test (no WAF present → no false positive), and a
      scope/plan-gating test mirroring `test_dns_only_module_skips_fingerprinting`.

---

## Phase 2 — Recon primitives that actually matter for bug bounty

This is the highest-leverage phase for you specifically. Prioritized by
how often each thing actually finds something in a real program.

- [ ] **JS file harvesting + parsing** (`core/js_intel.py`) — by far the
      highest-value addition:
  - [ ] Collect every `<script src>` from the main page + crawled pages
        (you already extract scripts in `_extract_scripts`; this reuses
        and extends that).
  - [ ] Fetch and regex/AST-scan JS bundles for: absolute/relative API
        endpoint paths, `fetch(...)`/`axios.get(...)` call targets,
        hardcoded subdomains, AWS/GCP/Azure keys and other high-entropy
        secrets (report *pattern matched*, never log the full secret
        value to disk/console — redact to first/last 4 chars), internal
        hostnames leaked in source maps.
  - [ ] Source map discovery (`*.js.map`) — when present, these often
        leak original file structure/comments/internal paths. Parse if
        found, don't try to guess/bruteforce map URLs.
  - [ ] This is also your answer to the SPA problem you found on your
        own site: even without full JS execution, parsing the bundles
        for `window.__NEXT_DATA__`-style hydration payloads or embedded
        API base URLs recovers a lot of the signal you'd otherwise only
        get from headless rendering.
- [ ] **Parameter mining** — collect candidate parameter names from JS,
      forms, and crawled URLs into a per-target wordlist
      (`--export-params`). Doesn't test anything, just surfaces what a
      later fuzzing tool (ffuf/Arjun) should target — keeps Inoue in
      "recon," hands off the "testing" to purpose-built tools.
- [ ] **Subdomain takeover fingerprinting** — you already have
      `discover_subdomains`; extend with a `--check-takeover` pass that
      matches CNAME targets against the well-known
      "service exists but this specific resource doesn't" fingerprint
      list (S3 `NoSuchBucket`, GitHub Pages `There isn't a GitHub Pages
      site here`, Heroku `no such app`, Azure, Fastly, etc.). This is
      read-only (just a GET) and one of the highest-signal/lowest-effort
      bug classes in bounty programs.
- [ ] **Cloud storage bucket discovery** — permutate the target's
      name/subdomain list against S3/GCS/Azure Blob naming conventions
      and check existence + public-listing status via a plain GET (no
      auth bypass attempts). Report bucket existence and whether listing
      is public; never attempt to write/delete.
- [ ] **API surface discovery** — probe for (don't brute force, just
      check the handful of near-universal conventional paths)
      `/swagger.json`, `/openapi.json`, `/api-docs`, `/.well-known/`,
      GraphQL `/graphql` + a single introspection query (introspection
      being *enabled* is itself the finding — report it, don't chain
      further queries off it).
- [ ] **Security header / CORS misconfig grading** — you already collect
      headers; add a report mode that grades CSP/HSTS/X-Frame-Options
      presence and flags `Access-Control-Allow-Origin: *` combined with
      `Access-Control-Allow-Credentials: true` (a real, common, and
      entirely passive-to-detect misconfig).
- [ ] **Sensitive file / exposure sweep** — extend `_enumerate_directories`
      beyond the current small guess list with a curated (not massive
      brute-force) set of near-universal exposure paths: `.env`,
      `.git/config`, `.git/HEAD`, `.DS_Store`, `docker-compose.yml`,
      `.aws/credentials`, backup file patterns (`.bak`, `~`, `.old`).
      Keep this bounded and rate-limited — this is the one area where
      "more paths" tips from recon into wordlist-brute-force territory,
      which most programs explicitly restrict.
- [ ] Tests: fixture-based for every new signal (mocked responses), plus
      a scope-respecting integration test for each active-ish check.

---

## Phase 3 — Full-site / JS-aware detection

The core limitation you already identified: static HTML/header fetching
misses anything client-rendered. Two tracks, cheapest-first.

- [ ] **Cheap wins without a browser** (do these before touching Playwright):
  - [ ] DOM/global-variable signature type: extend the signature schema
        with a `js_globals` field (`window.__NEXT_DATA__`,
        `window.Vue`, `window.React`, `ng-version` attribute, etc.) and
        match them against the JS bundles collected in Phase 2 instead
        of requiring execution — catches a surprising amount of SPA
        framework detection for free.
  - [ ] Hydration payload parsing: Next.js/Nuxt/Remix all embed a JSON
        blob in the initial HTML (`__NEXT_DATA__`, `window.__NUXT__`)
        even before JS runs — parse it directly, no rendering needed.
- [ ] **Headless rendering fallback** (`--render`, opt-in, heavier):
  - [ ] Playwright-based single-page render, triggered automatically
        only when static detection returns near-zero technologies (the
        signal you found on your own site) or explicitly via `--render`.
  - [ ] Capture: final rendered DOM (re-run fingerprinting against it),
        `window` global variable dump (for the `js_globals` signatures
        above), console errors (sometimes leak internal paths/versions),
        and network requests fired during render (a free API-endpoint
        discovery pass, folding into Phase 2's parameter mining).
  - [ ] Screenshot capture (`--screenshot`) — useful for bug bounty
        report evidence and for visually triaging a large target list
        fast. Store alongside the scan result, not inline in JSON.
  - [ ] Keep this fully optional and gracefully degrading — Playwright
        browser binaries are a heavy, non-trivial dependency; the tool
        must work identically without it, just with reduced SPA coverage
        (same pattern as the existing TLS-fingerprint optional-dependency
        handling).
- [ ] **Sitemap/robots-driven crawl expansion** — feed `sitemap.xml` and
      `robots.txt` `Disallow`/`Sitemap:` entries into the existing
      `--crawl` candidate list (currently just same-origin `<a href>`
      links) for much better page coverage without arbitrary depth.
- [ ] Tests: fixture HTML with `__NEXT_DATA__`/`window.Vue`, mocked
      Playwright render, screenshot path handling with Playwright absent.

---

## Phase 4 — Output & tool-chain integration

Bug bounty work is rarely done with one tool; make Inoue play well with
the rest of the stack instead of trying to replace it.

- [ ] `--export-nuclei` already exists — extend it with WAF-aware
      templates tags (skip templates known to trigger easy blocks when a
      WAF was detected, unless `--force`).
- [ ] `--export-amass`/`--export-subfinder`-style subdomain list export
      (you already discover subdomains; just need the output adapter).
- [ ] Markdown/HTML report: add WAF, JS-intel findings, and takeover
      candidates as new report sections (the renderer already exists in
      `inoue.py`, this is additive).
- [ ] Multi-target dashboard mode: given a program's full scope file,
      run `scan_many` across it and produce one aggregate report ranked
      by "interesting" (WAF absent, takeover candidate found, exposed
      `.git`, low security-header grade) — the actual bug-bounty workflow
      is "triage 200 subdomains fast," not "deep-scan one target."
- [ ] Tests: export format schema tests, aggregate-ranking unit tests.

---

## Phase 5 — Catalog quality & scale (pay down technical debt)

You already found the real problem here live-testing against github.com:
generic HTML-token signatures produce false positives (Microsoft IIS,
"Foundation" flagged on a site that runs neither). This gets worse, not
better, as you add more active checks feeding more text into the matcher.

- [ ] Audit and tighten the noisiest existing signatures — require
      header/meta corroboration (not HTML-token-only) for anything
      flagged as a specific commercial product (a signature that fires
      on the HTML substring "iis" alone is a false-positive generator).
- [ ] Add a `--strict` mode that raises the minimum confidence score
      required to report a detection (useful once WAF/JS-intel add more
      candidate text to match against).
- [ ] Expand the favicon and WAF-block-page catalogs incrementally using
      `scripts/collect_favicon_hash.py` — treat catalog growth as an
      ongoing, verified, cited process, not a batch import.
- [ ] Benchmark scan time as modules stack up (WAF probe + JS intel +
      crawl + optional render) and make sure `--fast` stays genuinely
      fast — it should still skip all of Phase 1–3 by default.

---

## Suggested order if you can only do a few things

1. Phase 0 scope guardrails — do this before Phase 1/2 make more requests.
2. Phase 1 WAF detection (your explicit ask, high value, mostly passive).
3. Phase 2 JS intel + subdomain takeover — highest bug-bounty ROI per
   engineering hour.
4. Phase 3 cheap JS-global signatures (skip Playwright initially).
5. Phase 5 catalog tightening — do this continuously, not as a "later."
6. Phase 3 headless rendering + Phase 4 tool-chain integration — biggest
   effort, do once the above is solid.
