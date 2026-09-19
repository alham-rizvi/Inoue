# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Passive WAF/CDN detection.

Deliberately separate from `Detection` / `fingerprints/signatures.py`:
"what's in front of this site" (Cloudflare, Akamai, Imperva...) is a
different question from "what's the site built with" (Next.js, nginx...),
and a bug bounty workflow cares about them differently - a WAF changes
what testing is even possible, so it should never get buried in a list of
40 other detected technologies.

Every signature here is a **passive** signal: header names/values or
cookie names that show up on essentially every response from that vendor,
with zero extra requests. No block-page probing, no payloads, nothing
that could be mistaken for testing the WAF's rules - this module only
reads what the target already sent for the page you asked it to fetch.
"""

from __future__ import annotations

import re


class WAFDetection:
    __slots__ = ("name", "vendor", "category", "confidence", "evidence")

    def __init__(self, name: str, vendor: str, category: str, confidence: str, evidence: str):
        self.name = name
        self.vendor = vendor
        self.category = category  # "WAF" or "CDN" - a lot of vendors are both
        self.confidence = confidence
        self.evidence = evidence

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "vendor": self.vendor,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


# Each entry: (name, vendor, category, [(kind, key, value_pattern_or_None), ...])
# kind is "header" or "cookie". value_pattern_or_None: None means "key
# present at all is enough"; otherwise a compiled-at-use regex must match
# the value. Any single match is sufficient (these are OR'd, not AND'd) -
# vendors don't reliably send every one of their own headers on every path.
_CATALOG = [
    ("Cloudflare", "Cloudflare", "WAF/CDN", [
        ("header", "cf-ray", None),
        ("header", "cf-cache-status", None),
        ("header", "server", r"^cloudflare$"),
        ("cookie", "__cfduid", None),
        ("cookie", "cf_clearance", None),
    ]),
    ("AWS CloudFront", "Amazon", "CDN", [
        ("header", "x-amz-cf-id", None),
        ("header", "x-amz-cf-pop", None),
        ("header", "via", r"cloudfront"),
    ]),
    ("AWS WAF", "Amazon", "WAF", [
        ("header", "x-amzn-waf-action", None),
        ("header", "x-amzn-requestid", None),
        ("cookie", "awsalb", None),
        ("cookie", "awsalbcors", None),
    ]),
    ("Akamai", "Akamai", "WAF/CDN", [
        ("header", "x-akamai-transformed", None),
        ("header", "akamai-origin-hop", None),
        ("header", "x-akamai-request-id", None),
        ("header", "server", r"akamaighost"),
    ]),
    ("Imperva Incapsula", "Imperva", "WAF", [
        ("header", "x-iinfo", None),
        ("header", "x-cdn", r"incapsula"),
        ("cookie", "incap_ses", None),
        ("cookie", "visid_incap", None),
    ]),
    ("Sucuri", "Sucuri", "WAF", [
        ("header", "x-sucuri-id", None),
        ("header", "x-sucuri-cache", None),
        ("header", "server", r"sucuri"),
    ]),
    ("Fastly", "Fastly", "CDN", [
        ("header", "x-served-by", r"cache-"),
        ("header", "x-fastly-request-id", None),
        ("header", "via", r"fastly"),
    ]),
    ("Azure Front Door / WAF", "Microsoft", "WAF/CDN", [
        ("header", "x-azure-ref", None),
        ("header", "x-fd-healthprobe", None),
        ("header", "x-msedge-ref", None),
    ]),
    ("F5 BIG-IP ASM", "F5", "WAF", [
        ("cookie", "bigipserver", None),
        ("header", "server", r"big-?ip"),
    ]),
    ("Barracuda WAF", "Barracuda", "WAF", [
        ("cookie", "barra_counter_session", None),
        ("header", "server", r"barracuda"),
    ]),
    ("Distil Networks", "Imperva", "WAF", [
        ("header", "x-distil-cs", None),
    ]),
    ("StackPath", "StackPath", "CDN", [
        ("header", "x-hw", None),
        ("header", "server", r"stackpath"),
    ]),
    ("Wallarm", "Wallarm", "WAF", [
        ("header", "x-wallarm-status", None),
        ("header", "nel", r"wallarm"),
    ]),
    ("Vercel Edge Network", "Vercel", "CDN", [
        ("header", "x-vercel-id", None),
        ("header", "x-vercel-cache", None),
    ]),
]


def _get_header(headers: dict, name: str) -> str:
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    return str(lowered.get(name.lower(), ""))


def detect_waf(headers: dict, cookies: dict) -> list[dict]:
    """Passive WAF/CDN detection from headers and cookies already collected
    during the normal page fetch - no extra requests, no probing."""
    cookie_values = {str(k).lower(): str(v) for k, v in (cookies or {}).items()}
    cookie_names = set(cookie_values.keys())
    findings: list[WAFDetection] = []

    for name, vendor, category, signals in _CATALOG:
        matched_evidence = None
        for kind, key, pattern in signals:
            if kind == "header":
                value = _get_header(headers, key)
                if not value:
                    continue
                if pattern is None or re.search(pattern, value, re.IGNORECASE):
                    matched_evidence = f"Header {key}: {value[:80]}"
                    break
            elif kind == "cookie":
                matching = [c for c in cookie_names if c == key or c.startswith(key)]
                if matching:
                    cookie_value = cookie_values.get(matching[0], "")
                    if pattern is None or re.search(pattern, cookie_value, re.IGNORECASE):
                        matched_evidence = f"Cookie: {matching[0]}"
                        break
        if matched_evidence:
            findings.append(WAFDetection(name, vendor, category, "medium", matched_evidence))

    return [f.to_dict() for f in findings]
