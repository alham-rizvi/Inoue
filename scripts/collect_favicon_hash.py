#!/usr/bin/env python3
# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Fetch a target's favicon and print its hash(es) as a ready-to-paste entry
for fingerprints/favicon_hashes.py.

Usage:
    python scripts/collect_favicon_hash.py <url> [technology_name] [category]

Example:
    python scripts/collect_favicon_hash.py https://wordpress.org "WordPress" "CMS"
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402

from core.favicon import compute_favicon_hash, extract_favicon_href  # noqa: E402


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    url = sys.argv[1]
    name = sys.argv[2] if len(sys.argv) > 2 else "UNKNOWN"
    category = sys.argv[3] if len(sys.argv) > 3 else "Other"
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
        page = client.get(url, headers={"User-Agent": "Mozilla/5.0"})
        favicon_url = extract_favicon_href(page.text, str(page.url))
        favicon_resp = client.get(favicon_url, headers={"User-Agent": "Mozilla/5.0"})
        favicon_resp.raise_for_status()

    hashes = compute_favicon_hash(favicon_resp.content)
    if not hashes:
        print("No favicon bytes were returned - nothing to hash.")
        return 1

    print(f"Favicon: {favicon_url}")
    print(f"Bytes:   {len(favicon_resp.content)}")
    print()
    for algo, value in hashes.items():
        print(f'    "{algo}:{value}": ("{name}", "{category}"),')
    print()
    if "mmh3" not in hashes:
        print("Note: install the optional 'mmh3' package for Shodan-style hashes:")
        print("  pip install mmh3")
    print(
        "Verify this favicon is actually representative (not a CDN default, "
        "not cached from a different site) before adding it to the catalog."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
