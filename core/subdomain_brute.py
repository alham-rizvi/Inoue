# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Active subdomain discovery by DNS wordlist bruteforce.

Inoue's existing subdomain path is passive: it reads certificate transparency
logs (crt.sh) and reports the hostnames some CA chose to publish. That is
cheap and safe, but it only ever sees names that ended up in a certificate.
Whole classes of real infrastructure are invisible to it - an ``intranet`` or
``jenkins`` host that is internal-only and never got a public cert, a
``staging`` box that reuses a parent's wildcard certificate and therefore has
no distinct crt.sh entry of its own, or any service that simply has not been
re-issued a certificate since it was deployed. Resolving a list of common
labels directly against the zone covers exactly that gap: no third-party API,
no request to the target's HTTP stack, only DNS queries a resolver already
performs for any other lookup.

THE WILDCARD PROBLEM - WHY FILTERING IS THE WHOLE POINT
------------------------------------------------------
A large number of zones publish a wildcard record (``*.example.com A 1.2.3.4``)
so that any name resolves. In such a zone *every* word in a wordlist "resolves,
because the wildcard answers for all of them. A naive bruteforcer therefore
reports hundreds of subdomains that do not exist - each one answering with the
identical wildcard address. This is not a cosmetic flaw; it is the single
largest source of bogus subdomain findings and it turns a useful recon module
into a false-positive generator that erodes trust in every other finding.

To prevent that, this module detects the wildcard FIRST, before the wordlist is
applied at all: it resolves two random, guaranteed-not-to-exist labels and, if
either one answers, marks the zone as wildcarded and records the wildcard's
address set. Only then does the brute force run, and any candidate whose
resolved addresses match that wildcard set is discarded instead of reported as
"found". Without this step, a single wildcard zone would make the output
worthless, so the detection is mandatory and runs on every invocation.

Everything here is read-only DNS. The discovered hosts are never contacted.
"""

from __future__ import annotations

import concurrent.futures
import secrets
import threading

# Common subdomain labels, embedded so the module works with no external file.
# Deliberately weighted towards names that indicate real, interesting
# infrastructure (mail, vpn, ci, admin, internal, ...) rather than being an
# exhaustive dictionary - this is a recon default, not a fuzzing corpus.
_DEFAULT_WORDLIST: tuple[str, ...] = (
    "www", "mail", "api", "dev", "staging", "test", "portal", "admin", "app",
    "blog", "shop", "store", "cdn", "static", "assets", "img", "images",
    "media", "video", "ftp", "sftp", "ssh", "vpn", "remote", "gateway", "ns1",
    "ns2", "dns", "mx", "smtp", "imap", "pop", "webmail", "email",
    "autodiscover", "intranet", "internal", "secure", "sso", "auth", "login",
    "id", "accounts", "support", "help", "docs", "wiki", "git", "gitlab",
    "github", "jenkins", "ci", "cd", "build", "deploy", "staging2", "qa",
    "uat", "demo", "sandbox", "beta", "alpha", "test2", "old", "new",
    "backup", "db", "database", "sql", "mysql", "redis", "cache", "queue",
    "mq", "kafka", "elastic", "grafana", "prometheus", "metrics", "status",
    "monitor", "edge", "origin", "proxy", "lb", "waf", "cpanel", "whm",
    "plesk", "webdisk", "cloud", "s3", "storage", "files", "drive", "print",
    "voip", "sip",
)

# Environment tokens used to build bounded permutations of names that were
# actually found. `dev-api.example.com` / `api-dev.example.com` are common
# enough to be worth the extra queries, but the variants are only ever derived
# from confirmed hits so the search space stays tied to reality.
_ENV_PREFIXES: tuple[str, ...] = ("dev-", "staging-", "test-", "prod-", "qa-")
_ENV_SUFFIXES: tuple[str, ...] = ("-dev", "-staging", "-test", "-prod", "-internal", "-api")

# Thread-local resolver cache. dnspython's Resolver object is reused per worker
# thread (so each thread pays configuration cost once) rather than shared
# across threads, where its internal state is not guaranteed concurrency-safe.
_STATE = threading.local()


def _normalize_domain(domain: str) -> str:
    """Reduce an arbitrary target string to a bare, lowercase domain."""
    text = str(domain or "").strip().lower()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    text = text.strip().strip(".")
    # Drop a port if one was supplied; host:port is not a DNS name.
    if text.count(":") == 1:
        text = text.split(":", 1)[0]
    return text


def _thread_resolver(timeout: int):
    """Return this thread's Resolver, (re)configured for the given timeout."""
    import dns.resolver

    resolver = getattr(_STATE, "resolver", None)
    if resolver is None or getattr(_STATE, "timeout", None) != timeout:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        _STATE.resolver = resolver
        _STATE.timeout = timeout
    return resolver


def _lookup(host: str, timeout: int) -> dict | None:
    """Resolve one hostname.

    Returns ``{"ips": [...], "cnames": [...]}`` on success, or ``None`` when
    the name genuinely does not resolve. NXDOMAIN and NoAnswer are normal
    misses. Only real resolver failures (timeout, SERVFAIL/NoNameservers) are
    re-raised, so the caller can record them as errors - a timeout must never
    be mistaken for a discovered host.
    """
    import dns.exception
    import dns.resolver

    resolver = _thread_resolver(timeout)
    ips: list[str] = []
    canonical: str | None = None
    answered = False

    for rtype in ("A", "AAAA"):
        try:
            answer = resolver.resolve(host, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # Real absence: the name exists in the query path but has no record.
            continue
        except (dns.resolver.Timeout, dns.resolver.NoNameservers):
            # Genuine resolver failure - propagate, never report as a hit.
            raise
        except dns.exception.DNSException:
            # Other protocol-level oddities are treated as a miss rather than
            # flooding the error list.
            continue
        answered = True
        for record in answer:
            address = getattr(record, "address", None)
            if address:
                ips.append(str(address))
        name = str(getattr(answer, "canonical_name", "") or "").rstrip(".")
        if name and name.lower() != host.lower():
            canonical = name

    if not answered and not ips:
        return None

    cnames: list[str] = []
    if canonical:
        cnames.append(canonical)
        # Walk the rest of the chain, but keep it strictly bounded so a
        # pathological CNAME loop cannot become an infinite query stream.
        current = canonical
        for _ in range(4):
            try:
                chain_answer = resolver.resolve(current, "CNAME")
            except Exception:
                break
            next_hop = None
            for record in chain_answer:
                next_hop = str(record.target).rstrip(".")
                break
            if not next_hop or next_hop == current:
                break
            cnames.append(next_hop)
            current = next_hop

    return {"ips": sorted(set(ips)), "cnames": cnames}


def _detect_wildcard(domain: str, timeout: int, errors: list[str]) -> dict:
    """Probe the zone for a wildcard record using two random labels.

    Two labels rather than one keeps the false-negative rate down: a single
    random name can miss by chance (negative caching, one bad nameserver in
    the pool), while two independent random names both answering is strong
    evidence of a `*.<domain>` record.
    """
    detected = False
    ips: set[str] = set()
    for _ in range(2):
        label = "inoue-wc-" + secrets.token_hex(4)
        try:
            hit = _lookup(f"{label}.{domain}", timeout)
        except Exception as exc:
            errors.append(f"wildcard probe {label}.{domain}: {type(exc).__name__}")
            hit = None
        if hit:
            detected = True
            ips.update(hit.get("ips") or [])
    return {"detected": detected, "ips": sorted(ips)}


def _permutations(label: str) -> list[str]:
    """Bounded env-style variants of a confirmed label."""
    variants: list[str] = []
    for prefix in _ENV_PREFIXES:
        variants.append(prefix + label)
    for suffix in _ENV_SUFFIXES:
        variants.append(label + suffix)
    return variants


def _leftmost_label(host: str, base: str) -> str:
    """Return the label(s) left of ``.<base>`` in ``host``, else ''."""
    if host.endswith("." + base):
        return host[: -(len(base) + 1)]
    return ""


def _run_lookups(hosts: list[str], timeout: int, workers: int, errors: list[str]) -> list[tuple[str, dict | None]]:
    """Resolve every host with a bounded thread pool.

    Real resolver errors are captured into ``errors`` (host + exception type)
    and yield a ``None`` hit, so a failed lookup can never masquerade as a
    discovered subdomain.
    """
    results: list[tuple[str, dict | None]] = []
    if not hosts:
        return results
    workers = max(1, min(int(workers), 100))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_lookup, host, timeout): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                results.append((host, future.result()))
            except Exception as exc:
                errors.append(f"{host}: {type(exc).__name__}")
    return results


def _keep(host: str, hit: dict | None, wildcard_ips: set[str]) -> dict | None:
    """Turn a raw lookup into a reportable entry, dropping wildcard echoes.

    A candidate is discarded when its addresses are a non-empty subset of the
    wildcard address set: such a host is indistinguishable from the wildcard
    placeholder and reporting it would be a false positive.
    """
    if not hit:
        return None
    ips = sorted(set(hit.get("ips") or []))
    cnames = hit.get("cnames") or []
    if wildcard_ips and ips and set(ips).issubset(wildcard_ips):
        return None
    if not ips and not cnames:
        return None
    return {"host": host, "ips": ips, "cnames": cnames}


def bruteforce(
    domain: str,
    wordlist: list[str] | None = None,
    timeout: int = 3,
    max_candidates: int = 200,
    workers: int = 20,
    permutations: bool = True,
) -> dict:
    """Bruteforce subdomains of ``domain`` from a wordlist.

    The zone is first probed for a wildcard record; if one exists, every
    candidate that merely echoes the wildcard addresses is filtered out (see
    the module docstring for why this is mandatory). Wordlist entries are then
    resolved against the zone with a bounded thread pool, and - when
    ``permutations`` is set - bounded env-style variants of the hosts that were
    actually found are tried as well.

    ``max_candidates`` hard-caps the total number of brute-force lookups
    (wordlist entries plus permutations), so a large wordlist or a slow
    resolver cannot turn into an unbounded scan. The two wildcard probes are
    not counted against it.

    This function never raises: unexpected conditions are reported through the
    ``issues`` and ``errors`` keys instead.

    Returns a dict with exactly these keys:
        domain (str): the normalized target.
        words_checked (int): wordlist entries actually resolved.
        found (list[dict]): hits as ``{"host", "ips", "cnames"}``.
        wildcard (dict): ``{"detected": bool, "ips": list[str]}``.
        permutations_checked (int): permutation candidates attempted.
        candidates_attempted (int): total brute-force lookups performed.
        issues (list[str]): human-readable notes (cap reached, wildcard seen...).
        errors (list[str]): genuine resolver failures, never reported as found.
    """
    result: dict = {
        "domain": domain,
        "words_checked": 0,
        "found": [],
        "wildcard": {"detected": False, "ips": []},
        "permutations_checked": 0,
        "candidates_attempted": 0,
        "issues": [],
        "errors": [],
    }

    try:
        base = _normalize_domain(domain)
    except Exception:
        base = ""
    result["domain"] = base
    if not base:
        result["issues"].append("empty or invalid domain - nothing to bruteforce")
        return result

    try:
        timeout = max(1, int(timeout))
    except Exception:
        timeout = 3
    try:
        workers = max(1, int(workers))
    except Exception:
        workers = 20
    try:
        cap = max(0, int(max_candidates))
    except Exception:
        cap = 200

    if cap == 0:
        result["issues"].append("max_candidates is 0 - no candidates were attempted")
        return result

    # Mandatory: establish whether the zone is wildcarded before believing any
    # wordlist hit. Order matters here - detection must precede the brute force.
    try:
        wildcard = _detect_wildcard(base, timeout, result["errors"])
    except Exception as exc:
        wildcard = {"detected": False, "ips": []}
        result["errors"].append(f"wildcard probe failed: {type(exc).__name__}")
    result["wildcard"] = wildcard
    wildcard_ips = set(wildcard.get("ips") or [])
    if wildcard.get("detected"):
        result["issues"].append(
            f"wildcard DNS detected for *.{base} - candidates resolving to the wildcard addresses were filtered out"
        )
        if not wildcard_ips:
            result["issues"].append(
                "wildcard record answered but no addresses were captured - IP-based filtering was unavailable"
            )

    # Build the base candidate set from the supplied or embedded wordlist.
    words: list[str] = []
    seen_words: set[str] = set()
    for raw in (wordlist if wordlist else _DEFAULT_WORDLIST):
        try:
            word = str(raw).strip().lower().strip(".")
        except Exception:
            continue
        if not word or word in seen_words:
            continue
        seen_words.add(word)
        words.append(word)

    base_hosts: list[str] = []
    seen_hosts: set[str] = set()
    for word in words:
        if len(base_hosts) >= cap:
            break
        host = f"{word}.{base}"
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        base_hosts.append(host)

    if len(words) > len(base_hosts):
        result["issues"].append(
            f"candidate cap reached: only {len(base_hosts)} of {len(words)} wordlist entries were attempted"
        )

    found: list[dict] = []
    for host, hit in _run_lookups(base_hosts, timeout, workers, result["errors"]):
        entry = _keep(host, hit, wildcard_ips)
        if entry:
            found.append(entry)
    result["words_checked"] = len(base_hosts)
    result["candidates_attempted"] = len(base_hosts)

    # Phase 2: permutations of hosts that were actually found.
    perm_hosts: list[str] = []
    if permutations:
        remaining = cap - result["candidates_attempted"]
        if remaining > 0 and found:
            for entry in found:
                label = _leftmost_label(entry["host"], base)
                if not label:
                    continue
                for variant in _permutations(label):
                    if len(perm_hosts) >= remaining:
                        break
                    host = f"{variant}.{base}"
                    if host in seen_hosts:
                        continue
                    seen_hosts.add(host)
                    perm_hosts.append(host)
                if len(perm_hosts) >= remaining:
                    break
            if perm_hosts:
                for host, hit in _run_lookups(perm_hosts, timeout, workers, result["errors"]):
                    entry = _keep(host, hit, wildcard_ips)
                    if entry:
                        found.append(entry)
            if remaining <= len(_permutations("x")) * len(found) and result["candidates_attempted"] + len(perm_hosts) >= cap:
                result["issues"].append("candidate cap reached while generating permutations")
        elif remaining <= 0:
            result["issues"].append("candidate cap reached before permutations could be attempted")

    result["found"] = sorted(found, key=lambda item: item["host"])
    result["permutations_checked"] = len(perm_hosts)
    result["candidates_attempted"] = len(base_hosts) + len(perm_hosts)
    return result
