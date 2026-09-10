# Inoue - Confirmed Bugs & Required Fixes

Compiled from live testing against `alhamrizvi.in` (and earlier
`flipkart.com`/`example.com` sandbox testing) on branch `main` /
`feature/best-in-class-recon`, build v1.1.2. Every item below was
reproduced with actual command output, not guessed - repro steps and
evidence are included so whoever fixes these can verify the fix against
the same case that found the bug.

Ordered by severity: **P0 (data integrity / silently wrong output)**,
**P1 (real bugs, lower blast radius)**, **P2 (missing implementation /
underdeveloped feature)**, **P3 (polish, hygiene, hardening)**.

---

## P0 - Data integrity bugs (silently wrong or non-deterministic output)

### P0-1. Version extractor treats timestamps/IDs as version numbers
**Where:** `core/scanner.py`, `_normalize_version()` (and by extension
`_extract_version()`, which calls it).

**Repro:** scan any Vercel-hosted site (`alhamrizvi.in`) repeatedly:
```
Run 1: "version": "1789011933767.02"
Run 2: "version": "6.17890119937…"
Run 3: "version": "1789012125429.63156"
Run 4: "version": "5.1789012131349.13281"
Run 5: "version": null
```
Evidence in every case is the same field: `X-Vercel-Id:
bom1::iad1::<random>-<13-digit-unix-ms-timestamp>-<random-hex>`. There is
no version in this header - it's a per-request trace ID. The bug: a bare
numeric string currently passes as a valid "version" via
`value.isdigit()` with no length ceiling, so a 13-digit timestamp is
accepted. The fallback regexes in `_extract_version()` then behave
unpredictably against the random hex/timestamp, producing a different
garbage value (or `None`) on every single run against the *same*
signature and *same* underlying evidence.

**Why P0, not P1:** this isn't an occasional miss - it fires on every
scan of a Vercel-hosted site, it's non-deterministic (same input class,
different output every time), and it corrupts any downstream use of the
`version` field (CVE version-matching, diffing between scans in watch
mode, any tooling built on the JSON contract). A "version" that changes
on every identical scan is actively worse than an honest `null`.

**Fix:**
```python
def _normalize_version(raw: str) -> Optional[str]:
    value = raw.strip().strip("'\";,:/\\")
    if not value:
        return None
    if value.lower().startswith(("version", "ver", "release", "build", "rev")):
        value = value.split(None, 1)[-1]
    value = value.replace("_", ".").replace("-", ".")
    value = re.sub(r"[^0-9.]+", "", value)
    if not value:
        return None
    if value.count("."):
        # still reject absurdly long dotted "versions" assembled from
        # a hex/timestamp string smashed together with stray dots
        if len(value.replace(".", "")) > 12:
            return None
        return value
    # Bare numeric-only candidates are only trustworthy as a version when
    # short. Long digit runs are timestamps, build IDs, or trace IDs,
    # not versions (e.g. Vercel's X-Vercel-Id contains a 13-digit
    # Unix-ms timestamp that was previously reported as a "version").
    return value if value.isdigit() and len(value) <= 5 else None
```
**Test to add:** fixture with an `X-Vercel-Id`-shaped header value must
always normalize to `None`, deterministically, across repeated calls with
different random suffixes (property-style test: generate 20 random
Vercel-ID-shaped strings, assert none produce a non-None version).

---

### P0-2. `-o report.md` does not write Markdown - writes raw JSON
**Where:** `inoue.py`, the output-saving branch in `main()` (the
extension-dispatch logic described as implemented in `CODEBASE_GUIDE.md`
section "10. Nuclei export format" / B3 "self-contained HTML report").

**Repro:**
```bash
python3 inoue.py -o /tmp/report.md alhamrizvi.in
cat /tmp/report.md
```
Output is a raw JSON array (`[{"url": ..., "technologies": [...] ...}]`),
byte-for-byte the same shape as `--json` output. No Markdown headers,
tables, or formatting anywhere in the file.

**Why P0:** this is silent - the CLI prints `saved /tmp/report.md` as if
it succeeded, with no error or warning. A user relying on this for a
client report or pentest write-up gets a broken file with zero
indication anything went wrong.

**Still to confirm:** whether `-o report.html` has the identical bug
(raw JSON with a `.html` extension) - untested as of this writing. Check
`cat /tmp/report.html` before fixing; if both are broken the same way,
it's one shared dispatch bug, not two separate ones.

**Fix:** locate wherever the "if output ends with .md" (and if it
exists, ".html") branching was supposed to happen in `main()`'s
output-saving code and verify it's (a) actually present, (b) actually
being reached (not shadowed by an earlier `if json_out or output:` branch
that always takes the JSON path first), and (c) actually calling the
Markdown/HTML generator function rather than falling through to the JSON
serializer. Add an integration test using `CliRunner` + a temp file that
asserts a `.md`-suffixed output file does NOT start with `[` or `{`
and DOES contain expected Markdown markers (`#`, `|---|`), and
equivalently for `.html` (`<html`/`<table`).

---

### P0-3. Whois errors print raw to stderr, bypassing the CLI's error handling entirely
**Where:** `core/scanner.py`, `_get_whois()`, or possibly the
`python-whois` dependency itself.

**Repro:**
```bash
python inoue.py --whois alhamrizvi.in
```
Output includes an unstyled, un-boxed line printed outside of Rich's
normal rendering:
```
Error trying to connect to socket: closing socket - [Errno -5] No address associated with hostname
```
This appears *before* the results table, with no `[error]`/`[dim]`
styling, and the scan then proceeds to render a normal-looking results
table as if nothing went wrong - a user could easily miss that whois
silently failed.

**Why P0 not P1:** this breaks the tool's error-handling contract
entirely for this module - a real failure is invisible/easy to miss
rather than being surfaced as structured data. If `--json` output is
checked, does `whois_info`/an equivalent field contain `{"error": ...}`,
or is it empty/missing entirely? **Needs a `--json --whois` test run to
confirm severity precisely** - if the JSON output silently has no error
field at all, treat this as P0; if it does surface the error into JSON
correctly and this is purely a terminal-cosmetics issue, downgrade to
P1.

**Fix approach:** if `python-whois`'s underlying socket module is
printing directly to stderr internally (some versions of this package do
exactly this rather than raising a catchable exception), wrap the whois
call in an explicit stderr redirect (`contextlib.redirect_stderr`) inside
`_get_whois()` so the tool controls all output paths, and turn whatever
was captured into the structured `{"error": "..."}` return value it
should already be producing on exception.

---

## P1 - Confirmed detection-accuracy bugs

### P1-1. "Ubuntu (OS)" false-positives on unrelated page copy
**Where:** `fingerprints/signatures.py`, the `Ubuntu` signature's `html`
pattern.

**Repro:** `alhamrizvi.in` is a portfolio site styled as a fake Ubuntu
desktop UI. Its `<meta name="description">` literally contains the
string *"Interactive Ubuntu-style desktop portfolio"*. Evidence output:
```
HTML: …ontent="Interactive Ubuntu-style desktop portf…
```
This has zero relationship to the actual server/hosting OS (it's
Vercel/serverless). The signature is very likely a bare `r'ubuntu'`
substring match with no context requirement.

**Fix:** OS-category signatures should never rely on unanchored HTML
body substring matching - page copy routinely contains OS/distro names
in totally unrelated contexts (this exact case, plus tutorials, blog
posts about Linux, portfolio themes, etc.). Either:
- Remove the bare `html` pattern for OS-category signatures entirely and
  require header-based evidence only (e.g. `Server: Apache/2.4
  (Ubuntu)`, `X-Powered-By` containing distro info), or
- If HTML matching must stay, require much more specific context (e.g.
  `Ubuntu Linux` AND proximity to a version number AND NOT inside a
  `<meta name="description">`/`<title>` tag - this is fragile, prefer
  removing HTML matching for this category).

**General rule to codify** (add to `CODEBASE_GUIDE.md` as a new
numbered decision): *OS-category signatures must not match on HTML body
text alone.*

**Test to add:** fixture with `<meta name="description" content="...
Ubuntu-style desktop...">` and no `Server` header mentioning Ubuntu must
NOT produce an Ubuntu detection.

---

### P1-2. Signature confidence for weak HTML-only matches may be overstated
**Where:** `fingerprints/signatures.py` + scoring logic (A1 work).

**Observation:** Tailwind CSS matched on a single generic HTML class
attribute (`class="flex h-screen w-screen items-cent…"`) and correctly
got `confidence: low` / `confidence_score: 12.0` - this one looks fine.
But GitBook matched on a `<link href="/assets/gitbook-xfFsj1tJ.js">` - a
build-hashed asset filename - and got `confidence: medium` /
`confidence_score: 28.8`. This is a stronger signal than a generic CSS
class (asset filename directly containing the product name), so on
reflection this one may actually be correctly scored; **flagging for a
manual confidence-calibration review pass across a wider sample of
sites, not a proven bug** - include in the Week 1 verification sweep
(A1 manual-check items) rather than assuming it's broken.

---

## P2 - Missing / incomplete implementation ("underdeveloped")

These are places where the tool's behavior suggests a feature was
scaffolded (flag exists, help text exists) but the underlying logic is
thin, absent, or a placeholder. Each needs verification against real
output before being called "done" - treat every checkbox in prior status
docs as unverified until re-confirmed per the Week 1 reconciliation
process already documented in the roadmap.

- **`--tls-fingerprint`**: output field `"tls_fingerprint": ""` appeared
  empty in every `--json` run so far, even without the flag being passed
  (it's present as a field in the schema regardless). Untested whether
  passing `--tls-fingerprint` explicitly ever populates it. **Action:**
  run `python3 inoue.py --tls-fingerprint -v -e alhamrizvi.in` and check
  whether the field populates, and whether a graceful-skip message
  appears if the optional dependency isn't installed. If it never
  populates even with the optional dependency present, this feature is
  not actually wired up despite being documented as implemented.
- **`--cve` / `--fail-on-cve` / `--cve-min-severity`**: every scan so far
  shows `"cves": []` on every technology, which is *expected* here since
  none of the detected tech (GitBook, Tailwind, HSTS, Vercel, and the
  false-positive Ubuntu) has known CVEs in a reasonable dataset - so this
  isn't evidence of a bug by itself. **Action:** test against a target
  with a technology+version that has a *known* CVE (e.g. an old,
  intentionally-outdated WordPress or Apache instance, or a
  fixture/local test server) to confirm the CVE correlation path
  actually fires end-to-end, and confirm `--fail-on-cve` actually returns
  exit code 2 (`echo $?` after the run) rather than 0.
- **`--cache`**: untested whether a second run actually skips
  recon/produces a "cache hit" indicator. Run the flag twice in a row and
  diff response timing + look for a cache-hit progress message.
- **`notes` field** (contradiction detection, A3): every run so far shows
  `"notes": []`. Untested against a target that would actually produce a
  contradiction (e.g. conflicting server signals). Needs a deliberate
  test case, not just organic testing against sites that happen not to
  trigger it.
- **`--nuclei-out`**: not yet tested in this session - confirm it
  produces valid, correctly-shaped output (see original agent-prompt
  spec) rather than another instance of the JSON-passthrough bug found
  in P0-2.
- **API (`api/` / FastAPI)**: not tested at all in this session. Given
  the JSON-export dispatch bug found in the CLI, the API layer (which
  per `CODEBASE_GUIDE.md` should reuse the same result serializer) needs
  explicit verification that it doesn't share the same bug, plus the
  full test matrix from the original agent prompt (`/health`,
  `/signatures`, `/scan`, `/scan/batch`, rate limiting, auth).
- **Watch mode (`watch` subcommand)**: not present in the `--help`
  output captured so far - confirm whether this subcommand exists at all
  in the current build, or is still purely aspirational per the roadmap
  doc's self-contradicting completed/pending list.

## P2 additional - Status-tracking integrity (carried over, still open)

The original roadmap status doc listed A4, A5, B1, B2, D3 as **both**
completed and next-priority work. **This was never actually reconciled**
in this session - every item above under "Missing / incomplete
implementation" is downstream of that unresolved contradiction. Until
someone runs the actual reconciliation audit (`git log` cross-referenced
against every "[x]" checkbox), no "Completed" claim in any prior status
document should be trusted without a fresh manual check like the ones
listed above.

---

## P3 - Polish, hygiene, hardening

- **`__pycache__` tracked in git** (fixed once already in an earlier
  branch - confirm it hasn't regressed on `main`/this branch;
  `git status --short` after a normal run should show no `.pyc` changes).
- **Duplicate signature keys** (e.g. HubSpot defined twice identically in
  `fingerprints/signatures.py`) - cosmetic today since duplicates are
  identical, but `scripts/check_signatures.py` should be run and its
  output attached to a PR before merging any signature-catalog changes,
  to prevent a future duplicate that ISN'T identical from silently
  shadowing the real definition.
- **Progress-log line count vs. terminal width**: cosmetic table
  rendering truncation seen in `-v -e` output (`vers…`, `con…`,
  `Frame…`, `Header` wrapping oddly) - not a functional bug, but worth a
  pass on `render_result()`'s column-width logic if this tool is meant to
  look professional in client-facing use (pentest report screenshots,
  etc.).
- **Timestamp/trace-ID leak as a minor info-hygiene issue**: not a
  security bug (these are already public in HTTP response headers
  anyway), but worth noting `X-Vercel-Id` values captured during testing
  are real trace IDs from a real Vercel deployment - no action needed,
  just don't paste raw evidence strings from real infrastructure into
  public bug trackers/issues without considering whether the target
  owner is fine with that (in this case it's the user's own site, so
  it's fine here).

---

## Suggested fix order (single next session)

1. **P0-1** (version normalization) - one function, clear repro, clear
   fix, immediately stops corrupting every Vercel-hosted scan's version
   field and any downstream CVE/diff logic that trusts it.
2. **P0-2** (`.md`/`.html` export) - confirm `.html` shares the bug,
   then fix the shared dispatch logic once for both.
3. **P0-3** (whois stderr leak) - confirm severity via `--json --whois`
   first, then fix.
4. **P1-1** (Ubuntu false positive) - one signature edit + one test.
5. Everything under **P2** - each needs a dedicated verification run
   before any further feature work is layered on top, per the existing
   roadmap's Week 1 reconciliation plan. Do not add new features to a
   subsystem until its existing "done" claim has been manually
   re-verified with real command output, the same way P0-1 through P1-1
   above were found: by actually running the command and reading the
   output critically, not by trusting a checkbox.
