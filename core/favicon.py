# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Favicon hashing for cheap, high-signal technology fingerprinting.

Favicons are a strong fingerprinting signal used by tools like Shodan,
BuiltWith, and EyeWitness: the bytes rarely change between deployments of
the same software/theme, they're a single small request, and they still
identify a stack even when HTML/headers have been stripped or minified.

Two hash algorithms are computed when possible:
  - md5   of the raw favicon bytes (always available, stdlib only)
  - mmh3  of the base64-encoded favicon bytes, matching the convention
          popularized by Shodan's `http.favicon.hash` field (requires the
          optional `mmh3` package; falls back to None when unavailable)
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Optional
from urllib.parse import urljoin

try:  # pragma: no cover - optional dependency
    import mmh3
except ImportError:  # pragma: no cover - optional dependency
    mmh3 = None

from fingerprints.favicon_hashes import FAVICON_HASHES

_ICON_REL_PATTERN = re.compile(
    r'<link[^>]+rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\'][^>]*href=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_ICON_REL_PATTERN_REVERSED = re.compile(
    r'<link[^>]+href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut icon|icon|apple-touch-icon)["\']',
    re.IGNORECASE,
)


def extract_favicon_href(body: str, base_url: str) -> str:
    """Find a declared favicon href in the page, falling back to /favicon.ico."""
    if body:
        match = _ICON_REL_PATTERN.search(body) or _ICON_REL_PATTERN_REVERSED.search(body)
        if match:
            return urljoin(base_url, match.group(1))
    return urljoin(base_url, "/favicon.ico")


def compute_favicon_hash(content: bytes) -> dict:
    """Return every favicon fingerprint we can compute for this content."""
    if not content:
        return {}
    result: dict = {"md5": hashlib.md5(content).hexdigest()}
    if mmh3 is not None:
        try:
            encoded = base64.b64encode(content)
            result["mmh3"] = mmh3.hash(encoded)
        except Exception:  # pragma: no cover - defensive
            pass
    return result


def match_favicon_hash(hashes: dict) -> Optional[tuple[str, str]]:
    """Look up a computed favicon hash against the known catalog.

    Returns (technology_name, category) on a hit, else None.
    Checks mmh3 first since it's the more widely cross-referenced value.
    """
    for algo in ("mmh3", "md5"):
        value = hashes.get(algo)
        if value is None:
            continue
        entry = FAVICON_HASHES.get(f"{algo}:{value}")
        if entry:
            return entry
    return None
