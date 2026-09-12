# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Known favicon hash -> (technology, category) catalog.

Keys follow the format "<algorithm>:<hash>", e.g.:
    "md5:d41d8cd98f00b204e9800998ecf8427e"
    "mmh3:-1157139415"

`mmh3` hashes follow the widely used Shodan-style convention:
    mmh3.hash(base64.b64encode(favicon_bytes))

This catalog intentionally ships EMPTY. Favicon bytes vary across
software versions, themes, and CDNs that recompress images - a wrong or
stale hash produces a false positive, which is worse than no signal at
all. Populate this file yourself with hashes you have verified against a
known-good instance of the technology, using the helper script:

    python scripts/collect_favicon_hash.py https://known-instance.example "TechName" "Category"

The script prints a ready-to-paste dict entry. Add it below, run
`python scripts/audit_signatures.py` (or the test suite) to sanity-check
the catalog, and keep a short comment noting the source/date you
verified it against, the same way `fingerprints/signatures.py` tracks
`since`/`source`/`last_verified` for its entries.
"""

FAVICON_HASHES: dict[str, tuple[str, str]] = {
    # Example (NOT a verified value - replace before relying on it):
    # "mmh3:-1157139415": ("Jenkins", "Development"),
}
