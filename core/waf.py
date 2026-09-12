"""Dedicated WAF/CDN detection. Signals are passive unless probe=True is requested."""
from __future__ import annotations

import re
import secrets
from dataclasses import asdict, dataclass
from urllib.parse import urljoin

import httpx


@dataclass
class WAFDetection:
    name: str
    vendor: str
    confidence: str
    evidence: str


_HEADER_RULES = [
    ("Cloudflare", "Cloudflare", "cf-ray", re.compile(r".+", re.I)),
    ("Cloudflare", "Cloudflare", "cf-cache-status", re.compile(r".+", re.I)),
    ("Sucuri", "Sucuri", "x-sucuri-id", re.compile(r".+", re.I)),
    ("Akamai", "Akamai", "x-akamai-", re.compile(r".+", re.I)),
    ("Incapsula", "Imperva/Incapsula", "x-iinfo", re.compile(r".+", re.I)),
    ("Distil Networks", "Distil", "x-distil-cs", re.compile(r".+", re.I)),
    ("FortiWeb", "Fortinet", "x-fw-hash", re.compile(r".+", re.I)),
    ("CloudFront", "AWS", "server", re.compile(r"cloudfront", re.I)),
]
_COOKIE_RULES = [
    ("Cloudflare", "Cloudflare", re.compile(r"^__(?:cfduid|cf_clearance)$", re.I)),
    ("Imperva/Incapsula", "Imperva/Incapsula", re.compile(r"^(?:incap_ses_|visid_incap_)", re.I)),
    ("AWS WAF/ALB", "AWS", re.compile(r"^AWSALB(?:CORS)?$", re.I)),
]
_BLOCK_RULES = [
    ("Cloudflare", re.compile(r"cloudflare|cf-ray|attention required", re.I)),
    ("Akamai", re.compile(r"akamai|reference\s*#\d+", re.I)),
    ("Imperva/Incapsula", re.compile(r"incapsula|imperva|incident id", re.I)),
    ("Sucuri", re.compile(r"sucuri website firewall|sucuri", re.I)),
    ("F5 BIG-IP ASM", re.compile(r"request rejected|the requested url was rejected", re.I)),
    ("Barracuda", re.compile(r"barracuda web application firewall", re.I)),
]


def detect_waf(headers: dict, cookies: dict | None = None, block_body: str = "") -> list[WAFDetection]:
    found: dict[str, WAFDetection] = {}
    lowered = {str(k).lower(): str(v) for k, v in headers.items()}
    for name, vendor, header, pattern in _HEADER_RULES:
        for key, value in lowered.items():
            if key == header or (header.endswith("-") and key.startswith(header)):
                if pattern.search(value):
                    found.setdefault(name, WAFDetection(name, vendor, "high", f"header {key}: {value[:80]}"))
    for name, vendor, pattern in _COOKIE_RULES:
        for key in (cookies or {}):
            if pattern.search(str(key)):
                found.setdefault(name, WAFDetection(name, vendor, "high", f"cookie {key}"))
    status_body = block_body or ""
    for name, pattern in _BLOCK_RULES:
        match = pattern.search(status_body)
        if match:
            found.setdefault(name, WAFDetection(name, name, "medium", f"block-page text: {match.group(0)[:60]}"))
    return list(found.values())


def probe_waf(url: str, timeout: int = 5, client: httpx.Client | None = None) -> list[WAFDetection]:
    path = f"/inoue-waf-probe-{secrets.token_hex(12)}"
    own_client = client is None
    session = client or httpx.Client(timeout=timeout, verify=False, follow_redirects=True)
    try:
        response = session.get(urljoin(url, path), headers={"Accept": "text/html", "User-Agent": "Inoue/1.0 read-only recon"})
        if response.status_code in {403, 406, 429}:
            return detect_waf(dict(response.headers), dict(response.cookies), response.text)
        return []
    except Exception:
        return []
    finally:
        if own_client:
            session.close()


def serialize_waf(detections: list[WAFDetection]) -> list[dict]:
    return [asdict(item) for item in detections]
