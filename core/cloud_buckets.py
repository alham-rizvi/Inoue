# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Public cloud storage bucket enumeration from a domain's naming convention.

A publicly listable object-store bucket (AWS S3, Google Cloud Storage, Azure
Blob) remains one of the highest-impact findings a recon pass can surface,
because a single open bucket frequently contains backups, database dumps,
customer exports or build artefacts. The check here is deliberately passive:
we only ask each provider's own public endpoint whether a name is in use,
which is exactly what any visitor with a browser could do. Nothing is written,
modified or deleted - listing is a read-only, anonymous GET.

FALSE POSITIVE RISK is the central concern and shapes the whole return shape.
A bucket that merely EXISTS is not, on its own, a vulnerability - plenty of
organisations legitimately reserve names they keep private. So the result of
every probe is classified explicitly and machine-readably:

  * HTTP 200 from the provider's listing endpoint -> the anonymous caller was
    handed the object listing. Reported with listable=True and accessible=True.
  * HTTP 403 (S3/GCS) or 400/403 (Azure Blob) carrying the provider's own error
    document -> the name EXISTS but the provider refused anonymous access.
    Reported with listable=False, accessible=False. This must never be
    described as an exposure.
  * HTTP 404, or the provider endpoint's hostname failing to resolve
    (NXDOMAIN-style) -> the name is definitively not in use and is dropped from
    the result entirely.
  * Anything else - a timeout, a connection error that is not a
    name-resolution failure, or a status the provider's contract does not
    define (503, 429, a WAF block) -> NO VERDICT. The probe is recorded in
    ``unverified`` instead of being turned into a claim: a transient network
    condition must not be read as "the bucket does not exist", and an
    infrastructure failure must certainly not be read as "the bucket exists".

Because a bare status code can be fabricated by wildcard DNS or a captive
proxy, a 200 is only upgraded to listable=True when the body actually looks
like the provider's listing payload (the provider XML markers). A 200 whose
body does not match is still surfaced - the name does exist - but with
accessible=False and an explanatory `detail`, so it can never be misread as a
confirmed public bucket.

Every probe is wrapped individually: one timeout or transport error degrades to
partial data (an entry in ``unverified``, plus ``errors`` for transport
failures) instead of aborting the whole pass. Exactly one request is made per
(candidate, provider) pair and the candidate list is hard-capped by
``max_candidates``, so the call stays light on both sides.
"""

from __future__ import annotations

import re
import socket
from typing import Optional

import httpx

try:  # declared dependency; guarded so importing this module can never raise
    import tldextract
except ImportError:  # pragma: no cover - defensive
    tldextract = None

# A fixed, ordinary browser identity. Bucket endpoints do not care, but a
# stable UA keeps our traffic indistinguishable from a normal visitor.
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# The bare registrable label first (most likely to exist), then the
# conventional decorations seen in the wild. Order is preserved and the whole
# list is truncated to max_candidates.
_SUFFIXES = [
    "",  # <label>
    "-backup",
    "-backups",
    "-dev",
    "-staging",
    "-prod",
    "-assets",
    "-static",
    "-media",
    "-uploads",
    "-data",
    "-public",
]

# (provider label, URL template). Each template's {name} is the bucket name.
_PROVIDERS = (
    ("aws", "https://{name}.s3.amazonaws.com/"),
    ("gcs", "https://storage.googleapis.com/{name}"),
    ("azure", "https://{name}.blob.core.windows.net/"),
)

# Body markers proving a 200 is the provider's own listing document rather
# than some interception page. S3 and the GCS XML API both use the S3 schema;
# Azure Blob uses its own EnumerationResults schema.
_LISTING_MARKERS = {
    "aws": ("<ListBucketResult", "<Contents>"),
    "gcs": ("<ListBucketResult", "<Contents>"),
    "azure": ("<EnumerationResults", "<Blobs>"),
}

_AZURE_ERROR_CODE_RE = re.compile(r"<Code>\s*([^<\s]+)\s*</Code>", re.IGNORECASE)

# Bodies larger than this are truncated before any regex/marker inspection -
# listings are small, and this keeps a hostile/large response from ballooning.
_MAX_BODY_BYTES = 262_144


def _registrable_label(domain: str) -> str:
    """Return the second-level label for a domain (example.com -> "example").

    Falls back to a hand-rolled split when tldextract is unavailable or cannot
    make sense of the input, so a malformed target degrades to the obvious
    guess rather than raising.
    """
    candidate = (domain or "").strip().lower()
    # Strip scheme, credentials, port and path if a URL was handed in.
    candidate = re.sub(r"^[a-z][a-z0-9+.-]*://", "", candidate)
    candidate = candidate.split("@")[-1].split("/")[0].split("?")[0].split(":")[0]

    if tldextract is not None:
        try:
            extracted = tldextract.extract(candidate)
            if extracted.domain:
                return extracted.domain
        except Exception:
            pass

    parts = [part for part in candidate.split(".") if part]
    if len(parts) > 1 and parts[0] == "www":
        parts = parts[1:]
    return parts[0] if parts else candidate


def _bucket_safe(label: str) -> str:
    """Coerce a label into the character set bucket names allow."""
    cleaned = re.sub(r"[^a-z0-9.-]", "-", (label or "").lower())
    return re.sub(r"-{2,}", "-", cleaned).strip("-.")


def _candidates(label: str, max_candidates: int) -> list[str]:
    """Build the bounded candidate list, deduplicated and order-preserving."""
    base = _bucket_safe(label)
    if not base:
        return []
    names: list[str] = []
    for suffix in _SUFFIXES:
        name = f"{base}{suffix}"
        if name not in names:
            names.append(name)
    return names[: max(0, max_candidates)]


def _body_text(response: httpx.Response) -> str:
    """Decode a bounded prefix of the body for marker inspection."""
    try:
        return response.content[:_MAX_BODY_BYTES].decode("utf-8", "replace")
    except Exception:  # pragma: no cover - defensive
        return ""


def _is_listing(provider: str, text: str) -> bool:
    """True only when the body carries the provider's listing markers."""
    return any(marker in text for marker in _LISTING_MARKERS.get(provider, ()))


# Substrings a name-resolution failure carries across libc and resolver
# implementations. Only this specific condition is evidence of absence: the
# provider endpoint's own hostname failing to resolve means no bucket can be
# hosted under the name.
_RESOLUTION_FAILURE_MARKERS = (
    "name or service not known",              # glibc, EAI_NONAME / errno -2
    "nodename nor servname provided",         # macOS / BSD
    "temporary failure in name resolution",   # glibc, EAI_AGAIN
    "no address associated with hostname",
    "getaddrinfo failed",
)


def _is_name_resolution_failure(exc: BaseException) -> bool:
    """True only when a connect error is specifically a DNS resolution failure.

    A connection refused, a TLS error or a timeout says nothing about whether
    the bucket name is in use - those must reach no verdict rather than being
    reported as absence.
    """
    seen = 0
    current: BaseException | None = exc
    while current is not None and seen < 5:
        if isinstance(current, socket.gaierror):
            return True
        text = str(current).lower()
        if any(marker in text for marker in _RESOLUTION_FAILURE_MARKERS):
            return True
        current = current.__cause__ or current.__context__
        seen += 1
    return False


def _probe(provider: str, name: str, template: str, timeout: int) -> tuple[Optional[dict], Optional[dict]]:
    """Ask one provider about one name. Returns ``(entry, unverified)``.

    * ``(entry, None)``  - a verdict: the name exists (see the module docstring
      for how each status is classified).
    * ``(None, None)``   - the name is definitively not in use: a clean 404, or
      the provider endpoint's hostname failing to resolve.
    * ``(None, record)`` - no verdict could be reached. A timeout, a connect
      error that is not a name-resolution failure, or a status the provider's
      contract does not define is recorded instead of being turned into a claim
      about the bucket.

    Never raises.
    """
    url = template.format(name=name)

    def _no_verdict(reason: str, status: Optional[int] = None) -> tuple[None, dict]:
        return None, {"provider": provider, "name": name, "url": url, "status": status, "reason": reason}

    try:
        with httpx.Client(
            timeout=max(1, timeout),
            verify=False,
            follow_redirects=False,
        ) as client:
            response = client.get(url, headers={"User-Agent": _USER_AGENT})
    except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
        if _is_name_resolution_failure(exc):
            # The provider's own endpoint does not resolve => nothing can be
            # hosted under this name.
            return None, None
        return _no_verdict(f"{type(exc).__name__}: {exc}")
    except Exception as exc:  # read timeout, TLS oddity, protocol error...
        return _no_verdict(f"{type(exc).__name__}: {exc}")

    status = response.status_code
    if status == 404:
        return None, None

    text = _body_text(response)
    listing = status == 200 and _is_listing(provider, text)

    if status == 200:
        if listing:
            detail = "anonymous listing succeeded - bucket is publicly readable"
        else:
            detail = (
                "HTTP 200 but body does not match the provider listing format "
                "(likely interception/wildcard response) - presence unverified"
            )
        return {
            "provider": provider,
            "name": name,
            "url": url,
            "status": status,
            "accessible": listing,
            "listable": listing,
            "detail": detail,
        }, None

    code_match = _AZURE_ERROR_CODE_RE.search(text)
    code = f" ({code_match.group(1)})" if code_match else ""
    if status == 403 or (status == 400 and code_match):
        # A refusal the provider itself documents means the name exists and is
        # not public. A bare 400 carries no such evidence and falls through.
        return {
            "provider": provider,
            "name": name,
            "url": url,
            "status": status,
            "accessible": False,
            "listable": False,
            "detail": f"name exists but anonymous listing denied (HTTP {status}{code})",
        }, None

    # Any other status is the provider - or something in front of it - failing
    # to answer about the name. That is not evidence the bucket exists, and it
    # is not evidence that it does not.
    return _no_verdict(f"unexpected response (HTTP {status}{code}) - existence not established", status=status)


def enumerate_buckets(domain: str, timeout: int = 5, max_candidates: int = 12) -> dict:
    """Enumerate object-store buckets for a domain's naming convention.

    Probes each candidate name against AWS S3, Google Cloud Storage and Azure
    Blob. Returns only names that actually exist, each carrying an explicit
    ``listable`` flag so a private bucket is never overstated as an exposure.

    ``checked`` counts the individual HTTP probes issued
    (candidates x providers), which is the number bounded by ``max_candidates``.
    ``issues`` holds one plain-language line per existing bucket worth a human's
    attention; ``errors`` holds transport failures that prevented a verdict;
    ``unverified`` holds one structured record per probe that reached no verdict
    at all (a timeout, a connect error, an undefined status), so a lookup that
    failed is never read as evidence either way.
    """
    errors: list[str] = []
    issues: list[str] = []
    found: list[dict] = []
    unverified: list[dict] = []

    label = _registrable_label(domain)
    candidates = _candidates(label, max_candidates)

    checked = 0
    for name in candidates:
        for provider, template in _PROVIDERS:
            checked += 1
            entry, unknown = _probe(provider, name, template, timeout)
            if entry is not None:
                found.append(entry)
                if entry["listable"]:
                    issues.append(
                        f"{provider} bucket '{name}' is publicly listable - anonymous "
                        f"object listing exposed at {entry['url']}"
                    )
                else:
                    issues.append(
                        f"{provider} bucket '{name}' exists but denies anonymous "
                        f"listing (HTTP {entry['status']}) - confirm intent"
                    )
                continue
            if unknown is not None:
                unverified.append(unknown)
                if unknown["status"] is None:
                    # A transport failure is also surfaced in `errors`, which is
                    # the human-readable list of what went wrong.
                    errors.append(f"{provider} {name}: {unknown['reason']}")

    return {
        "domain": domain,
        "candidates": candidates,
        "found": found,
        "issues": issues,
        "errors": errors,
        "unverified": unverified,
        "checked": checked,
    }
