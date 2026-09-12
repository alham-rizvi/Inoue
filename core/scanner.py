# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Core scanning engine - fetches target and runs all detections concurrently.
"""

import os
import asyncio
import json
import ipaddress
import re
import socket
import ssl
import subprocess
import time
from contextlib import redirect_stderr
from io import StringIO
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

try:
    import whois
except ImportError:  # pragma: no cover - optional dependency
    whois = None

import httpx
from core.cache import ScanCache
from core.cve import correlate_cves, load_cve_dataset

from fingerprints.signatures import (
    COMPILED_SIGNATURES,
    SIGNATURES,
    SIGNATURES_BY_HEADER,
    SIGNATURES_BY_META,
    SIGNATURES_BY_COOKIE_TOKEN,
    SIGNATURES_BY_SCRIPT_TOKEN,
    SIGNATURES_BY_HTML_TOKEN,
    SIGNATURES_BY_PATH_TOKEN,
)



@dataclass
class Detection:
    name: str
    category: str
    version: Optional[str] = None
    confidence: str = "high"  # high / medium / low
    confidence_score: float = 0.0
    evidence: str = ""
    cves: list[dict] = field(default_factory=list)


@dataclass
class ScanResult:
    url: str
    final_url: str
    status_code: int
    response_time_ms: float
    ip: str = ""
    server: str = ""
    technologies: list = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    dns_records: dict = field(default_factory=dict)
    ssl_info: dict = field(default_factory=dict)
    tls_fingerprint: str = ""
    whois_info: dict = field(default_factory=dict)
    whois_summary: dict = field(default_factory=dict)
    subdomains: list = field(default_factory=list)
    mail_records: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    directories: list = field(default_factory=list)
    extra_intel: dict = field(default_factory=dict)
    error: Optional[str] = None
    enriched: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    cache_hit: bool = False


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

    digits_only = re.sub(r"\D", "", value)
    if digits_only:
        if len(digits_only) > 10:
            return None

    if "." in value:
        return value

    if value.isdigit():
        return value if len(value) <= 5 else None
    return None


def _extract_version(pattern: str, text: str) -> Optional[str]:
    """Try to pull a version string from a regex match group 1 or from nearby version-like text."""
    if not text:
        return None

    try:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            for idx in range(1, m.lastindex + 1 if m.lastindex else 1):
                value = m.group(idx)
                normalized = _normalize_version(str(value)) if value else None
                if normalized:
                    return normalized
    except re.error:
        pass

    patterns = [
        r'(?i)(?:v|version|ver|release|build|rev(?:ision)?)\s*[:=]?\s*(\d+(?:[._-]?\d+){1,3})',
        r'(?i)(?:^|[^a-z0-9])(?:v|version|ver|release)\s*(\d+(?:[._-]?\d+){1,3})',
        r'(?i)/(?:v|version|ver|release)?(?:[._-])?(\d+(?:[._-]?\d+){1,3})',
    ]
    for regex in patterns:
        try:
            matches = re.findall(regex, text)
            if matches:
                normalized = _normalize_version(matches[0])
                if normalized:
                    return normalized
        except re.error:
            continue

    try:
        version_matches = re.findall(r'(\d+(?:[._-]?\d+){1,3})', text)
        if version_matches:
            for candidate in version_matches:
                normalized = _normalize_version(candidate)
                if normalized and len(normalized.split('.')) >= 2:
                    return normalized
    except re.error:
        pass
    return None


def _match_headers(sig: dict, headers: dict) -> tuple[bool, Optional[str], str]:
    """Returns (matched, version, evidence)."""
    for header_name, pattern in sig.get("headers", {}).items():
        val = headers.get(header_name, "") or headers.get(header_name.lower(), "")
        if val and pattern.search(val):
            version = _extract_version(pattern.pattern if hasattr(pattern, "pattern") else str(pattern), val)
            return True, version, f"{header_name}: {val[:80]}"
    return False, None, ""


def _match_cookies(sig: dict, cookies: dict) -> tuple[bool, str]:
    for pattern in sig.get("cookies", []):
        for cookie_name in cookies:
            if pattern.search(cookie_name):
                return True, f"Cookie: {cookie_name}"
    return False, ""


def _match_html(sig: dict, body: str) -> tuple[bool, Optional[str], str]:
    for pattern in sig.get("html", []):
        m = pattern.search(body)
        if m:
            snippet = body[max(0, m.start()-20):m.end()+20].strip().replace("\n", " ")
            version = _extract_version(pattern.pattern if hasattr(pattern, "pattern") else str(pattern), body[m.start():m.end() + 80])
            return True, version, f"HTML: …{snippet[:60]}…"
    return False, None, ""


def _count_html_matches(sig: dict, body: str) -> int:
    return sum(1 for pattern in sig.get("html", []) if pattern.search(body))


def _filter_excluded_detections(detections: list[Detection]) -> list[Detection]:
    names = {detection.name for detection in detections}
    return [
        detection
        for detection in detections
        if not any(name in names for name in COMPILED_SIGNATURES.get(detection.name, {}).get("excludes", []))
    ]


def detect_contradictions(detections: list[Detection]) -> list[str]:
    servers = [detection.name for detection in detections if detection.category == "Web Server"]
    if len(servers) < 2:
        return []
    return [f"conflicting server signals: {', '.join(servers)} — possible reverse proxy"]


def _match_scripts(sig: dict, scripts: list[str]) -> tuple[bool, Optional[str], str]:
    for pattern in sig.get("scripts", []):
        for src in scripts:
            m = pattern.search(src)
            if m:
                version = None
                try:
                    version = m.group(1) if m.lastindex else None
                except IndexError:
                    pass
                if not version:
                    version = _extract_version(pattern.pattern if hasattr(pattern, "pattern") else str(pattern), src)
                return True, version, f"Script: {src[:80]}"
    return False, None, ""


def _match_meta(sig: dict, meta: dict) -> tuple[bool, Optional[str], str]:
    for meta_name, pattern in sig.get("meta", {}).items():
        val = meta.get(meta_name, "")
        if val and pattern.search(val):
            version = _extract_version(pattern.pattern if hasattr(pattern, "pattern") else str(pattern), val)
            return True, version, f"Meta {meta_name}: {val[:60]}"
    return False, None, ""


def _extract_scripts(body: str) -> list[str]:
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)


def _extract_meta(body: str) -> dict:
    meta = {}
    for m in re.finditer(r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE):
        meta[m.group(1).lower()] = m.group(2)
    for m in re.finditer(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE):
        meta[m.group(2).lower()] = m.group(1)
    return meta


def _parse_cert_datetime(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z") and "T" in text:
        return text
    try:
        from datetime import datetime, timezone
        dt = datetime.strptime(text, "%b %d %H:%M:%S %Y %Z")
        return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass
    return None


def _get_ssl_info(hostname: str) -> dict:
    payload = {"subject": {}, "issuer": {}, "notAfter": "", "notBefore": "", "version": "", "san": [], "protocol": "", "cipher": ""}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
            cert = s.getpeercert()
            payload.update({
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "notAfter": _parse_cert_datetime(cert.get("notAfter", "")) or cert.get("notAfter", ""),
                "notBefore": _parse_cert_datetime(cert.get("notBefore", "")) or cert.get("notBefore", ""),
                "version": cert.get("version", ""),
                "san": [x[1] for x in cert.get("subjectAltName", [])],
                "protocol": s.version(),
                "cipher": s.cipher()[0] if s.cipher() else "",
            })

            try:
                import sslyze  # type: ignore
                payload["sslyze_available"] = True
                payload["sslyze"] = {
                    "protocols": [s.version()],
                    "cipher": s.cipher()[0] if s.cipher() else "",
                    "certificate_subject": payload.get("subject", {}),
                }
            except Exception:
                payload["sslyze_available"] = False

            return payload
    except Exception as e:
        return {"error": str(e)}


def _get_active_tls_inventory(hostname: str) -> dict:
    try:
        import nmap
    except Exception:
        return {"error": "python-nmap is not installed"}
    try:
        nm = nmap.PortScanner()
        result = nm.scan(hostname, arguments='-sV -p 443,8443,80,8080 --open')
        hosts = result.get('scan', {})
        if not hosts:
            return {"services": []}
        services = []
        for host, details in hosts.items():
            for port, info in details.get('tcp', {}).items():
                if info.get('state') == 'open':
                    services.append({
                        'port': port,
                        'state': info.get('state'),
                        'name': info.get('name', 'unknown'),
                        'product': info.get('product', ''),
                        'version': info.get('version', ''),
                    })
        return {"services": services}
    except Exception as exc:
        return {"error": str(exc)}


def _get_dns(hostname: str) -> dict:
    records = {}
    try:
        import dns.resolver
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(hostname, rtype, lifetime=2)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
    except ImportError:
        # fallback: just A record via socket
        try:
            infos = socket.getaddrinfo(hostname, None)
            records["A"] = list({i[4][0] for i in infos if i[0] == socket.AF_INET})
            records["AAAA"] = list({i[4][0] for i in infos if i[0] == socket.AF_INET6})
        except Exception:
            pass
    return records


def _resolve_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return ""


SMART_TOKENS = {
    "hs-scripts": "HubSpot",
    "hubspot": "HubSpot",
    "googletagmanager": "Google Tag Manager",
    "google-analytics": "Google Analytics",
    "gtag": "Google Analytics",
    "stripe": "Stripe",
    "mailchimp": "Mailchimp",
    "hotjar": "Hotjar",
    "mixpanel": "Mixpanel",
    "segment": "Segment",
    "facebook": "Meta Pixel",
    "pinterest": "Pinterest",
    "sentry": "Sentry",
    "shopify": "Shopify",
    "wp-admin": "WordPress",
    "phpmyadmin": "phpMyAdmin",
    "jenkins": "Jenkins",
    "grafana": "Grafana",
    "kibana": "Kibana",
    "graphql": "GraphQL",
    "swagger": "Swagger UI",
    "openapi": "OpenAPI",
    "wp-json": "WordPress REST API",
    "api-docs": "Swagger UI",
    "docs": "Swagger UI",
}


def build_recon_plan(requested: Optional[list[str]] = None) -> dict:
    modules = {
        "headers": False,
        "dns": False,
        "ssl": False,
        "whois": False,
        "subdomains": False,
        "mail": False,
        "tech": False,
        "ports": False,
        "extra": False,
        "smart": False,
        "active": False,
        "passive": False,
        "company": False,
        "cve": False,
    }
    if not requested:
        modules.update({"headers": True, "tech": True, "smart": True})
        return modules

    selected = set()
    for item in requested:
        selected.add(item.lower())

    full_recon = "full-recon" in selected or "full_recon" in selected or "all" in selected
    fast_scan = "fast" in selected or "fast-scan" in selected or "fast_scan" in selected
    smart_scan = "smart" in selected or "smart-detect" in selected or "smart_detect" in selected
    active_recon = "active" in selected or "active-recon" in selected or "active_recon" in selected
    passive_recon = "passive" in selected or "passive-recon" in selected or "passive_recon" in selected
    company_intel = "company" in selected or "site" in selected or "organization" in selected
    cve_correlation = "cve" in selected or "cves" in selected

    for key in modules:
        modules[key] = full_recon or key in selected

    if smart_scan:
        modules["smart"] = True
    if active_recon:
        modules["active"] = True
        modules["subdomains"] = True
        modules["ports"] = True
        modules["extra"] = True
    if passive_recon:
        modules["passive"] = True
        modules["subdomains"] = True
        modules["extra"] = True
    if company_intel:
        modules["company"] = True
        modules["extra"] = True
    if cve_correlation:
        modules["cve"] = True

    if fast_scan:
        modules.update({
            "headers": True,
            "dns": False,
            "ssl": False,
            "whois": False,
            "subdomains": False,
            "mail": False,
            "tech": True,
            "ports": False,
            "extra": False,
            "smart": True,
        })

    if "intel" in selected:
        modules["extra"] = True
    if full_recon:
        modules.update({
            "headers": True,
            "dns": True,
            "ssl": True,
            "whois": True,
            "subdomains": True,
            "mail": True,
            "tech": True,
            "ports": True,
            "extra": True,
            "smart": True,
            "active": True,
            "passive": True,
            "company": True,
        })
    return modules


def summarize_whois_details(whois_data: dict) -> dict:
    def pick(*keys):
        for key in keys:
            value = whois_data.get(key)
            if isinstance(value, (list, tuple, set)):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        return item.strip()
            elif isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    nameservers = []
    for value in [whois_data.get("name_servers"), whois_data.get("nameservers")]:
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if isinstance(item, str) and item.strip():
                    nameservers.append(item.strip())
        elif isinstance(value, str) and value.strip():
            nameservers.append(value.strip())

    return {
        "domain": pick("domain_name", "domain", "domainName"),
        "company": pick("organization", "org", "registrant_organization", "company"),
        "registrant": pick("registrant", "registrant_name", "admin_name", "name"),
        "country": pick("registrant_country", "country", "country_code"),
        "registrar": pick("registrar", "registrar_name", "sponsoring_registrar"),
        "creation_date": pick("creation_date", "created", "created_date"),
        "expiration_date": pick("expiration_date", "expires", "expires_date"),
        "nameservers": nameservers,
    }


def merge_subdomain_candidates(active: list[str], passive: list[str]) -> list[str]:
    merged = []
    seen = set()
    for entry in active + passive:
        if not isinstance(entry, str):
            continue
        candidate = entry.strip().lower().rstrip(".")
        if candidate and candidate not in seen:
            seen.add(candidate)
            merged.append(candidate)
    return sorted(merged)


def _get_whois(hostname: str) -> dict:
    if not whois:
        return {"error": "python-whois is not installed"}
    stderr_buffer = StringIO()
    try:
        with redirect_stderr(stderr_buffer):
            data = whois.whois(hostname)
        captured_error = stderr_buffer.getvalue().strip()
        if captured_error:
            return {"error": captured_error}
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if v}
        return {"raw": str(data)}
    except Exception as exc:
        captured_error = stderr_buffer.getvalue().strip()
        return {"error": captured_error or str(exc)}


def _get_mail_records(hostname: str) -> list[str]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "MX", lifetime=3)
        return sorted(str(r.exchange).rstrip(".") for r in answers)
    except Exception:
        return []


def _guess_subdomains(hostname: str) -> list[str]:
    common = [
        "www", "mail", "login", "admin", "portal", "api", "dev", "test", "staging",
        "blog", "cpanel", "webmail", "mx", "ns1", "ns2", "ftp", "smtp", "imap",
        "autodiscover", "cloud", "vpn", "remote", "cdn", "assets", "files",
    ]
    found = []
    for prefix in common:
        candidate = f"{prefix}.{hostname}"
        try:
            socket.gethostbyname(candidate)
            found.append(candidate)
        except Exception:
            continue
    return sorted(found)


def _fetch_passive_subdomains(hostname: str) -> list[str]:
    names = []
    try:
        with httpx.Client(timeout=3, verify=True) as client:
            response = client.get(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=4)
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, list):
                    for item in data:
                        value = item.get("name_value") if isinstance(item, dict) else ""
                        if isinstance(value, str):
                            for entry in value.splitlines():
                                entry = entry.strip()
                                if entry and entry.endswith(hostname) and entry != hostname:
                                    names.append(entry)
    except Exception:
        pass
    return sorted(set(names))


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target must be an HTTP or HTTPS URL")
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(parsed.hostname, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ValueError("target hostname could not be resolved") from exc
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ValueError("private and non-public targets are disabled")


def _get_with_redirect_policy(client, url: str, headers: dict, timeout: int, follow_redirects: bool, allow_private_targets: bool):
    if allow_private_targets:
        return client.get(url, headers=headers, follow_redirects=follow_redirects, timeout=timeout)
    current = url
    for _ in range(10):
        _validate_public_url(current)
        response = client.get(current, headers=headers, follow_redirects=False, timeout=timeout)
        if not follow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        current = urljoin(current, location)
    raise ValueError("redirect limit exceeded")


async def _async_get_with_redirect_policy(client, url: str, headers: dict, timeout: int, follow_redirects: bool, allow_private_targets: bool):
    if allow_private_targets:
        return await client.get(url, headers=headers, follow_redirects=follow_redirects, timeout=timeout)
    current = url
    for _ in range(10):
        await asyncio.to_thread(_validate_public_url, current)
        response = await client.get(current, headers=headers, follow_redirects=False, timeout=timeout)
        if not follow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("location")
        if not location:
            return response
        current = urljoin(current, location)
    raise ValueError("redirect limit exceeded")


def discover_subdomains(hostname: str) -> list[str]:
    active = _guess_subdomains(hostname)
    passive = _fetch_passive_subdomains(hostname)
    return merge_subdomain_candidates(active, passive)


def _enumerate_directories(url: str, headers: dict, body: str, timeout: int = 2) -> list[dict]:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    common_paths = [
        "/", "/admin", "/login", "/dashboard", "/api", "/wp-admin", "/phpmyadmin",
        "/robots.txt", "/sitemap.xml", "/.well-known", "/assets", "/uploads",
        "/backup", "/cms", "/portal", "/manager", "/health", "/metrics",
    ]
    matches = []

    def probe(path: str) -> Optional[dict]:
        candidate_url = base + path
        try:
            with httpx.Client(timeout=max(1, timeout), verify=False) as client:
                response = client.get(candidate_url, headers={"User-Agent": headers.get("User-Agent", "Mozilla/5.0")}, follow_redirects=True)
            if response.status_code < 500:
                return {
                    "path": path,
                    "url": str(response.url),
                    "status_code": response.status_code,
                    "source": "active",
                }
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=min(8, len(common_paths))) as executor:
        for match in executor.map(probe, common_paths):
            if match:
                matches.append(match)

    if body:
        for href in re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
            if href.startswith("http"):
                continue
            clean = href.split("#", 1)[0].split("?", 1)[0]
            if clean and clean.startswith("/") and clean.count("/") <= 2:
                matches.append({"path": clean, "url": base + clean, "status_code": 0, "source": "scrape"})

    seen = {}
    for item in matches:
        key = item["path"]
        if key not in seen:
            seen[key] = item
    return sorted(seen.values(), key=lambda item: (item["source"] != "active", item["path"]))


def _extract_html_intel(body: str) -> dict:
    intel = {}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        if title:
            intel["title"] = title
        headings = [h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2", "h3"]) if h.get_text(" ", strip=True)]
        if headings:
            intel["headings"] = headings[:10]
        links = [link.get("href") for link in soup.find_all("a", href=True) if link.get("href")][:20]
        if links:
            intel["links"] = links
        canonical = soup.find("link", rel=lambda value: value and "canonical" in value.lower())
        if canonical and canonical.get("href"):
            intel["canonical"] = canonical.get("href")
        meta_description = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
        if meta_description and meta_description.get("content"):
            intel["meta_description"] = meta_description.get("content")
    except Exception:
        pass
    return intel


def _fetch_public_intel(hostname: str, body: str = "") -> dict:
    intel = {}
    try:
        with httpx.Client(timeout=5, verify=True) as client:
            for url in [
                f"https://dns.google/resolve?name={hostname}&type=A",
                f"https://dns.google/resolve?name={hostname}&type=TXT",
            ]:
                try:
                    response = client.get(url)
                    if response.status_code == 200:
                        payload = response.json()
                        if isinstance(payload, dict):
                            intel.setdefault("public_dns", []).extend(payload.get("Answer", []))
                except Exception:
                    pass

            try:
                crt = client.get(f"https://crt.sh/?q=%25.{hostname}&output=json", timeout=8)
                if crt.status_code == 200:
                    data = crt.json()
                    if isinstance(data, list):
                        names = []
                        for item in data:
                            if isinstance(item, dict):
                                value = item.get("name_value")
                                if isinstance(value, str):
                                    names.extend([x.strip() for x in value.splitlines() if x.strip()])
                        intel["crt_sh"] = sorted(set(names))[:20]
            except Exception:
                pass
    except Exception:
        pass

    if body:
        intel["page_intel"] = _extract_html_intel(body)
    return intel


def _scan_common_ports(hostname: str, timeout: int = 1) -> list[dict]:
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 8080, 8443, 8888, 9000, 5900, 2375, 2376]
    def probe(port: int) -> Optional[dict]:
        try:
            with socket.create_connection((hostname, port), timeout=timeout):
                return {"port": port, "service": "unknown"}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=len(ports)) as executor:
        return [result for result in executor.map(probe, ports) if result]


def _collect_company_intel(hostname: str, body: str = "", headers: Optional[dict] = None) -> dict:
    intel = {}
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "html.parser")
        title = (soup.title.get_text(" ", strip=True) if soup.title else "") or ""
        if title:
            intel["title"] = title
        meta_description = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
        if meta_description and meta_description.get("content"):
            intel["meta_description"] = meta_description.get("content")
        canonical = soup.find("link", rel=lambda value: value and "canonical" in value.lower())
        if canonical and canonical.get("href"):
            intel["canonical"] = canonical.get("href")
    except Exception:
        pass

    if hostname:
        intel["hostname"] = hostname
    if headers:
        server = headers.get("server") or headers.get("Server")
        if server:
            intel["server"] = server
    return intel


def build_service_summary(result: ScanResult) -> list[dict]:
    summary = []
    for tech in result.technologies:
        summary.append({
            "name": tech.name,
            "category": tech.category,
            "version": tech.version or "unknown",
            "confidence": tech.confidence,
            "confidence_score": tech.confidence_score,
            "evidence": tech.evidence,
        })
    return summary


def _serialize_scan_result(result: ScanResult) -> dict:
    return {
        "url": result.url,
        "final_url": result.final_url,
        "status_code": result.status_code,
        "response_time_ms": result.response_time_ms,
        "ip": result.ip,
        "server": result.server,
        "technologies": [d.__dict__ for d in result.technologies],
        "headers": result.headers,
        "ssl_info": result.ssl_info,
        "tls_fingerprint": result.tls_fingerprint,
        "dns_records": result.dns_records,
        "whois_info": result.whois_info,
        "whois_summary": result.whois_summary,
        "subdomains": result.subdomains,
        "mail_records": result.mail_records,
        "open_ports": result.open_ports,
        "directories": result.directories,
        "extra_intel": result.extra_intel,
        "enriched": result.enriched,
        "error": result.error,
        "notes": result.notes,
        "cache_hit": result.cache_hit,
    }


def serialize_scan_result(result: ScanResult) -> dict:
    """Return the stable public JSON contract shared by API consumers."""
    return {
        "url": result.url,
        "final_url": result.final_url,
        "ip": result.ip,
        "status_code": result.status_code,
        "response_time_ms": result.response_time_ms,
        "server": result.server,
        "technologies": [detection.__dict__ for detection in result.technologies],
        "headers": result.headers,
        "dns": result.dns_records,
        "ssl": result.ssl_info,
        "tls_fingerprint": result.tls_fingerprint,
        "whois": result.whois_info,
        "whois_summary": result.whois_summary,
        "subdomains": result.subdomains,
        "mail_records": result.mail_records,
        "open_ports": result.open_ports,
        "directories": result.directories,
        "extra_intel": result.extra_intel,
        "recon": result.enriched.get("recon", []) if result.enriched else [],
        "service_hints": result.enriched.get("service_hints", []) if result.enriched else [],
        "plugins": result.enriched.get("plugins", {}) if result.enriched else {},
        "notes": result.notes,
        "error": result.error,
        "cache_hit": result.cache_hit,
    }


def _deserialize_scan_result(payload: dict) -> ScanResult:
    result = ScanResult(
        url=payload.get("url", ""),
        final_url=payload.get("final_url", ""),
        status_code=payload.get("status_code", 0),
        response_time_ms=payload.get("response_time_ms", 0),
        ip=payload.get("ip", ""),
        server=payload.get("server", ""),
        headers=payload.get("headers", {}),
        ssl_info=payload.get("ssl_info", {}),
        tls_fingerprint=payload.get("tls_fingerprint", ""),
        dns_records=payload.get("dns_records", {}),
        whois_info=payload.get("whois_info", {}),
        whois_summary=payload.get("whois_summary", {}),
        subdomains=payload.get("subdomains", []),
        mail_records=payload.get("mail_records", []),
        open_ports=payload.get("open_ports", []),
        directories=payload.get("directories", []),
        extra_intel=payload.get("extra_intel", {}),
        enriched=payload.get("enriched", {}),
        error=payload.get("error"),
        notes=payload.get("notes", []),
        cache_hit=bool(payload.get("cache_hit", False)),
    )
    result.technologies = [Detection(**item) for item in payload.get("technologies", [])]
    return result


def _scan_cache_module(
    timeout: int,
    follow_redirects: bool,
    dns: bool,
    ssl_check: bool,
    modules: Optional[list[str]],
    plugin_dirs: Optional[list[str]],
    cve_min_severity: Optional[str],
    api_key: Optional[str],
) -> str:
    options = {
        "timeout": timeout,
        "follow_redirects": follow_redirects,
        "dns": dns,
        "ssl": ssl_check,
        "modules": sorted(set(modules or [])),
        "plugin_dirs": sorted(str(path) for path in (plugin_dirs or [])),
        "cve_min_severity": cve_min_severity or "",
        "api_key": bool(api_key),
    }
    return "scan:" + json.dumps(options, sort_keys=True, separators=(",", ":"))


def _correlate_detection_cves(
    detections: list[Detection],
    dataset_path: Optional[str] = None,
    min_severity: Optional[str] = None,
) -> None:
    dataset = load_cve_dataset(dataset_path)
    for detection in detections:
        detection.cves = correlate_cves(detection.name, detection.version, dataset, min_severity)


def diff_scan_results(previous: ScanResult, current: ScanResult) -> dict:
    """Compare two scan results and summarize changes in technologies, CVEs, and ports."""
    previous_tech = {tech.name: tech for tech in previous.technologies}
    current_tech = {tech.name: tech for tech in current.technologies}

    technology_changes = []
    for name in sorted(set(previous_tech) | set(current_tech)):
        prev = previous_tech.get(name)
        curr = current_tech.get(name)
        if prev is None and curr is not None:
            technology_changes.append({"status": "added", "name": name, "version": curr.version})
        elif prev is not None and curr is None:
            technology_changes.append({"status": "removed", "name": name, "version": prev.version})
        elif prev is not None and curr is not None and prev.version != curr.version:
            technology_changes.append({"status": "changed", "name": name, "previous": prev.version, "current": curr.version})

    previous_cves = {item["id"] for tech in previous.technologies for item in tech.cves}
    current_cves = {item["id"] for tech in current.technologies for item in tech.cves}
    cve_changes = []
    for cve_id in sorted(current_cves - previous_cves):
        cve_changes.append({"status": "added", "id": cve_id})
    for cve_id in sorted(previous_cves - current_cves):
        cve_changes.append({"status": "removed", "id": cve_id})

    previous_ports = set(previous.open_ports)
    current_ports = set(current.open_ports)
    port_changes = {
        "added": sorted(current_ports - previous_ports),
        "removed": sorted(previous_ports - current_ports),
    }

    certificate_expiry = []
    expiry = current.ssl_info.get("notAfter") if isinstance(current.ssl_info, dict) else ""
    if expiry:
        try:
            from datetime import datetime
            normalized_expiry = _parse_cert_datetime(expiry)
            if not normalized_expiry:
                raise ValueError("unsupported certificate expiry format")
            expires = datetime.fromisoformat(normalized_expiry.replace("Z", "+00:00"))
            from datetime import timezone
            delta_days = (expires - datetime.now(timezone.utc)).days
            if delta_days <= 30:
                certificate_expiry.append({"expires": expiry, "days_remaining": delta_days})
        except Exception:
            pass

    return {
        "technology_changes": technology_changes,
        "cve_changes": cve_changes,
        "port_changes": port_changes,
        "certificate_expiry": certificate_expiry,
    }


def watch_scan_loop(
    targets: list[str],
    scan_fn: Callable[..., object],
    interval_seconds: float = 60,
    iterations: Optional[int] = None,
    sleep_fn: Optional[Callable[[float], None]] = None,
) -> list[object]:
    """Run a scan callback repeatedly for a target list with a delay between cycles."""
    if not targets:
        return []

    sleep = sleep_fn or time.sleep
    cycle_count = max(1, iterations) if iterations is not None else 1
    results: list[object] = []

    for cycle_index in range(cycle_count):
        for target in targets:
            try:
                result = scan_fn(target)
            except TypeError:
                result = scan_fn()
            results.append(result)
        if cycle_index < cycle_count - 1 and interval_seconds > 0:
            sleep(interval_seconds)

    return results


async def _async_scan_target(
    client: httpx.AsyncClient,
    url: str,
    timeout: int,
    follow_redirects: bool,
    modules: Optional[list[str]] = None,
    plugin_dirs: Optional[list[str]] = None,
    cve_min_severity: Optional[str] = None,
    dns_enabled: bool = True,
    ssl_enabled: bool = True,
    api_key: Optional[str] = None,
    progress: Optional[Callable[[str], None]] = None,
    allow_private_targets: bool = True,
) -> ScanResult:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }
    parsed = urlparse(url)
    result = ScanResult(url=url, final_url=url, status_code=0, response_time_ms=0)
    plan = build_recon_plan(modules)
    started = time.perf_counter()

    try:
        response = await _async_get_with_redirect_policy(
            client,
            url,
            headers=headers_to_send,
            follow_redirects=follow_redirects,
            timeout=timeout,
            allow_private_targets=allow_private_targets,
        )
    except httpx.ConnectError:
        if not url.startswith("https://"):
            result.error = "connection failed"
            return result
        try:
            response = await _async_get_with_redirect_policy(
                client,
                url.replace("https://", "http://", 1),
                headers=headers_to_send,
                follow_redirects=follow_redirects,
                timeout=timeout,
                allow_private_targets=allow_private_targets,
            )
        except Exception as exc:
            result.error = str(exc)
            return result
    except Exception as exc:
        result.error = str(exc)
        return result

    result.response_time_ms = round((time.perf_counter() - started) * 1000, 1)
    result.final_url = str(response.url)
    result.status_code = response.status_code
    parsed = urlparse(result.final_url)
    result.headers = dict(response.headers)
    result.server = result.headers.get("server", "")
    cookies = {key: value for key, value in response.cookies.items()}
    result.technologies = run_fingerprints(
        result.headers,
        cookies,
        response.text,
        url=result.final_url,
        progress=progress,
        sources={"headers"} if plan.get("headers") and not plan.get("tech") else None,
    )
    result.notes = detect_contradictions(result.technologies)
    if "cve" in (modules or []) or "cves" in (modules or []):
        _correlate_detection_cves(result.technologies, min_severity=cve_min_severity)
    hostname = parsed.hostname or ""
    result.ip = _resolve_ip(hostname)
    plan = build_recon_plan(modules)
    result.enriched = {
        "services": build_service_summary(result),
        "recon": build_recon_summary(result),
        "service_hints": [
            item for item in build_recon_summary(result) if item.get("service_hints")
        ],
    }
    if plan.get("headers"):
        result.enriched["headers"] = dict(result.headers)

    recon_results = {}
    tasks = []
    if plan.get("dns") and dns_enabled and hostname:
        tasks.append(("dns", lambda: _get_dns(hostname)))
    if plan.get("ssl") and ssl_enabled and hostname and parsed.scheme == "https":
        tasks.append(("ssl", lambda: _get_ssl_info(hostname)))
    if plan.get("whois") and hostname:
        tasks.append(("whois", lambda: _get_whois(hostname)))
    if plan.get("mail") and hostname:
        tasks.append(("mail", lambda: _get_mail_records(hostname)))
    if plan.get("subdomains") and hostname:
        tasks.append(("subdomains", lambda: discover_subdomains(hostname)))
    if plan.get("ports") and hostname:
        tasks.append(("ports", lambda: _scan_common_ports(hostname, timeout=max(1, min(3, timeout // 4)))))
    if plan.get("extra") and hostname:
        tasks.append(("extra", lambda: {
            "directories": _enumerate_directories(result.final_url, result.headers, response.text, timeout=max(1, min(2, timeout // 4))),
            "intel": _fetch_public_intel(hostname, response.text),
        }))
    if tasks:
        task_results = await asyncio.gather(
            *(asyncio.to_thread(task) for _, task in tasks),
            return_exceptions=True,
        )
        for (label, _), value in zip(tasks, task_results):
            recon_results[label] = None if isinstance(value, Exception) else value

    result.dns_records = recon_results.get("dns") or {}
    result.ssl_info = recon_results.get("ssl") or {}
    result.whois_info = recon_results.get("whois") or {}
    result.whois_summary = summarize_whois_details(result.whois_info)
    result.mail_records = recon_results.get("mail") or []
    result.subdomains = recon_results.get("subdomains") or []
    result.open_ports = recon_results.get("ports") or []
    extra_payload = recon_results.get("extra") or {}
    result.directories = extra_payload.get("directories") or []
    result.extra_intel = extra_payload.get("intel") or {}
    result.extra_intel.setdefault("directories", result.directories)
    company_intel = _collect_company_intel(hostname, response.text, result.headers)
    if company_intel:
        result.extra_intel.setdefault("company", {})
        result.extra_intel["company"].update(company_intel)
        result.enriched.setdefault("company", company_intel)
    if hostname:
        external = _enrich_with_external_services(hostname, [tech.name for tech in result.technologies], api_key)
        if external:
            result.enriched.update(external)
    from core.plugins import run_plugins
    plugin_results = run_plugins(result, plugin_dirs, progress)
    if plugin_results:
        result.enriched["plugins"] = plugin_results
    return result


async def scan_many(
    targets: list[str],
    timeout: int = 10,
    follow_redirects: bool = True,
    dns: bool = True,
    ssl_check: bool = True,
    api_key: Optional[str] = None,
    modules: Optional[list[str]] = None,
    workers: int = 5,
    rate_limit: Optional[float] = None,
    cache_path: Optional[str] = None,
    cache_ttl: int = 86400,
    plugin_dirs: Optional[list[str]] = None,
    progress: Optional[Callable[[str], None]] = None,
    cve_min_severity: Optional[str] = None,
    allow_private_targets: bool = True,
) -> list[ScanResult]:
    """Scan multiple targets concurrently using one shared async HTTP client."""
    if not targets:
        return []

    semaphore = asyncio.Semaphore(max(1, workers))
    cache = ScanCache(cache_path, cache_ttl) if cache_path else None
    host_locks: dict[str, asyncio.Lock] = {}
    host_last_request: dict[str, float] = {}

    async def wait_for_host_rate(target: str):
        if not rate_limit or rate_limit <= 0:
            return
        normalized = target if target.startswith(("http://", "https://")) else f"https://{target}"
        hostname = urlparse(normalized).hostname or normalized
        lock = host_locks.setdefault(hostname, asyncio.Lock())
        async with lock:
            interval = 1 / rate_limit
            now = time.monotonic()
            delay = interval - (now - host_last_request.get(hostname, 0))
            if delay > 0:
                await asyncio.sleep(delay)
            host_last_request[hostname] = time.monotonic()

    async def _scan_one(target: str) -> ScanResult:
        async with semaphore:
            if progress:
                progress(f"starting {target}")
            if cache:
                cache_module = _scan_cache_module(
                    timeout, follow_redirects, dns, ssl_check, modules,
                    plugin_dirs, cve_min_severity, api_key,
                )
                cached = cache.get(target, cache_module)
                if cached:
                    cached_result = _deserialize_scan_result(cached)
                    cached_result.cache_hit = True
                    if progress:
                        progress(f"using cached scan for {target}")
                    return cached_result
            await wait_for_host_rate(target)
            result = await _async_scan_target(
                client, target, timeout, follow_redirects, modules, plugin_dirs,
                cve_min_severity, dns, ssl_check, api_key, progress,
                allow_private_targets,
            )
            if cache and not result.error:
                cache.set(target, cache_module, _serialize_scan_result(result))
                result.cache_hit = False
            return result

    try:
        async with httpx.AsyncClient(verify=False) as client:
            tasks = [asyncio.create_task(_scan_one(target)) for target in targets]
            return list(await asyncio.gather(*tasks))
    finally:
        if cache is not None:
            cache.close()


async_scan_many = scan_many


def build_recon_summary(result: ScanResult) -> list[dict]:
    services = []
    for tech in result.technologies:
        hints = []
        if tech.name in {
            "Jenkins", "Nifi", "Tomcat", "Grafana", "Prometheus", "Kibana", "Jira",
            "Confluence", "GitLab", "Rancher", "Portainer", "OpenSSH", "Redis",
            "PostgreSQL", "MongoDB", "Elasticsearch", "RabbitMQ", "phpMyAdmin",
            "Webmin", "Adminer", "Apache Guacamole", "Zabbix", "Cacti", "Rundeck",
            "Plesk", "cPanel", "DirectAdmin"
        }:
            hints.append("Common exposed management or data service")
        if tech.name in {"Apache", "Nginx", "IIS", "Tomcat", "OpenSSH", "Jenkins", "GitLab"}:
            hints.append("Likely entrypoint or foothold service")
        if tech.version:
            hints.append("Version detected")
        services.append({
            "name": tech.name,
            "category": tech.category,
            "version": tech.version or "unknown",
            "confidence": tech.confidence,
            "evidence": tech.evidence,
            "service_hints": hints,
        })
    return services


def _enrich_with_external_services(hostname: str, technology_names: list[str], api_key: Optional[str] = None) -> dict:
    if not api_key:
        return {}

    try:
        endpoint = os.getenv("INOUE_ENRICHMENT_URL", "https://api.technitium.com")
        headers = {"Authorization": f"Bearer {api_key}"}
        with httpx.Client(timeout=5, verify=True) as client:
            response = client.get(f"{endpoint}/services/{hostname}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                return data if isinstance(data, dict) else {}
    except Exception:
        return {}
    return {}


def _tokenize_text(value: str, min_length: int = 4) -> set[str]:
    tokens = set()
    text = value.lower()
    for token in re.split(r"[^a-z0-9_./:-]+", text):
        if not token:
            continue
        if len(token) >= min_length:
            tokens.add(token)

        stripped = re.sub(r'^(https?:)?//', '', token)
        if len(stripped) >= min_length:
            tokens.add(stripped)

        parts = re.split(r"[./:-]+", token)
        for subtoken in parts:
            if len(subtoken) >= min_length:
                tokens.add(subtoken)

        stripped_parts = re.split(r"[./:-]+", stripped)
        for subtoken in stripped_parts:
            if len(subtoken) >= min_length:
                tokens.add(subtoken)

        if "." in stripped:
            host = stripped.split("/", 1)[0]
            segments = host.split(".")
            for idx in range(len(segments) - 1):
                suffix = ".".join(segments[idx:])
                if len(suffix) >= min_length:
                    tokens.add(suffix)
    return tokens


def _collect_candidate_signatures(
    headers: dict,
    meta: dict,
    cookies: dict,
    scripts: list[str],
    body: str,
    path: str,
) -> set[str]:
    candidates: set[str] = set()

    for header_name in headers:
        candidates.update(SIGNATURES_BY_HEADER.get(header_name.lower(), []))
    for meta_name in meta:
        candidates.update(SIGNATURES_BY_META.get(meta_name.lower(), []))
    for cookie_name in cookies:
        for token in _tokenize_text(cookie_name):
            candidates.update(SIGNATURES_BY_COOKIE_TOKEN.get(token, []))
    for script_src in scripts:
        for token in _tokenize_text(script_src):
            candidates.update(SIGNATURES_BY_SCRIPT_TOKEN.get(token, []))
        lower_src = script_src.lower()
        for token, tech_name in SMART_TOKENS.items():
            if token in lower_src:
                candidates.add(tech_name)
    html_candidates: set[str] = set()
    for token in _tokenize_text(body):
        html_candidates.update(SIGNATURES_BY_HTML_TOKEN.get(token, []))
        for smart_token, tech_name in SMART_TOKENS.items():
            if smart_token in token:
                candidates.add(tech_name)
    for token in _tokenize_text(path):
        candidates.update(SIGNATURES_BY_PATH_TOKEN.get(token, []))
        for smart_token, tech_name in SMART_TOKENS.items():
            if smart_token in token:
                candidates.add(tech_name)

    if len(candidates | html_candidates) > 1000:
        html_candidates = set()
        for token in _tokenize_text(body):
            if len(token) >= 9:
                html_candidates.update(SIGNATURES_BY_HTML_TOKEN.get(token, []))
    candidates.update(html_candidates)

    return candidates


def run_fingerprints(
    headers: dict,
    cookies: dict,
    body: str,
    url: str = "",
    progress: Optional[Callable[[str], None]] = None,
    sources: Optional[set[str]] = None,
) -> list[Detection]:
    def report(message: str):
        if progress:
            progress(message)

    scripts = _extract_scripts(body)
    meta = _extract_meta(body)
    detections = []
    path = ""
    seen_names = set()
    if url:
        try:
            parsed = urlparse(url)
            path = parsed.path or ""
        except Exception:
            path = ""

    report("starting fingerprint matching")
    candidate_names = _collect_candidate_signatures(headers, meta, cookies, scripts, body, path)
    if not candidate_names:
        report("no strong signature tokens found; evaluating full signature list")
        candidate_names = set(COMPILED_SIGNATURES)
    else:
        report(f"filtered to {len(candidate_names)} likely signatures")

    for tech_name in sorted(candidate_names):
        sig = COMPILED_SIGNATURES.get(tech_name)
        if not sig:
            continue
        category = sig.get("category", "Other")
        matched = False
        version = None
        evidence = ""
        confidence = "low"
        candidates = []

        h_match, h_ver, h_ev = _match_headers(sig, headers) if not sources or "headers" in sources else (False, None, "")
        if h_match:
            candidates.append((4, h_ver, h_ev))

        m_match, m_ver, m_ev = _match_meta(sig, meta) if not sources or "meta" in sources else (False, None, "")
        if m_match:
            candidates.append((3, m_ver, m_ev))

        s_match, s_ver, s_ev = _match_scripts(sig, scripts) if not sources or "scripts" in sources else (False, None, "")
        if s_match:
            candidates.append((2, s_ver, s_ev))

        b_match, b_ver, b_ev = _match_html(sig, body) if not sources or "html" in sources else (False, None, "")
        if b_match:
            candidates.append((1, b_ver, b_ev))

        c_match, c_ev = _match_cookies(sig, cookies) if not sources or "cookies" in sources else (False, "")
        if c_match:
            candidates.append((0, None, c_ev))

        if path and (not sources or "paths" in sources):
            for pattern in sig.get("paths", []):
                if pattern.search(path):
                    candidates.append((0, None, f"Path: {path}"))
                    break

        if candidates:
            matched = True
            best_rank, best_version, best_evidence = max(candidates, key=lambda item: item[0])
            version = best_version
            evidence = best_evidence
            for rank, candidate_version, candidate_evidence in sorted(candidates, key=lambda item: item[0], reverse=True):
                if candidate_version:
                    best_rank = rank
                    version = candidate_version
                    evidence = candidate_evidence
                    break

            signal_weights = {4: 40.0, 3: 35.0, 2: 25.0, 1: 12.0, 0: 10.0}
            score = sum(signal_weights[rank] for rank, _, _ in candidates)
            html_matches = _count_html_matches(sig, body)
            if html_matches > 1:
                score = score - signal_weights[1] + signal_weights[1] * (1 + 0.7 * (html_matches - 1))
            score *= 1 + min(0.5, 0.15 * max(0, len(candidates) - 1))
            confidence_score = round(min(100.0, score), 1)

            if confidence_score >= 70:
                confidence = "high"
            elif confidence_score >= 35:
                confidence = "high"
            elif confidence_score >= 20:
                confidence = "medium"
            else:
                confidence = "low"
        else:
            confidence_score = 0.0

        if matched:
            if tech_name not in seen_names:
                detections.append(Detection(
                    name=tech_name,
                    category=category,
                    version=version,
                    confidence=confidence,
                    confidence_score=confidence_score,
                    evidence=evidence,
                ))
                seen_names.add(tech_name)
                report(f"detected {tech_name} ({category})")
    detections = _filter_excluded_detections(detections)
    report(f"fingerprint matching complete ({len(detections)} detections)")

    if path:
        path_matches = [
            (r"/phpmyadmin", "phpMyAdmin", "Administration"),
            (r"/wp-admin|/wp-login\.php", "WordPress", "CMS"),
            (r"/wp-json(?:/|$)", "WordPress REST API", "API"),
            (r"/graphql(?:/|$)|/graphiql(?:/|$)|/graphql-ws(?:/|$)", "GraphQL", "API"),
            (r"/swagger(?:-ui)?(?:/|$)|/docs(?:/|$)|/redoc(?:/|$)", "Swagger UI", "API Docs"),
            (r"/openapi\.(?:json|yaml)(?:/|$)|/openapi(?:/|$)", "OpenAPI", "API Docs"),
            (r"/jenkins", "Jenkins", "Administration"),
            (r"/grafana", "Grafana", "Monitoring"),
            (r"/prometheus", "Prometheus", "Monitoring"),
            (r"/kibana", "Kibana", "Monitoring"),
            (r"/gitlab", "GitLab", "Development"),
            (r"/rundeck", "Rundeck", "Administration"),
            (r"/portainer", "Portainer", "Administration"),
            (r"/zabbix", "Zabbix", "Monitoring"),
            (r"/cacti", "Cacti", "Monitoring"),
        ]
        for pattern, tech_name, category in path_matches:
            if re.search(pattern, path, re.IGNORECASE) and tech_name not in seen_names:
                detections.append(Detection(
                    name=tech_name,
                    category=category,
                    confidence="high",
                    evidence=f"Path: {path}",
                ))
                seen_names.add(tech_name)

    return detections


def scan(
    url: str,
    timeout: int = 10,
    follow_redirects: bool = True,
    dns: bool = True,
    ssl_check: bool = True,
    api_key: Optional[str] = None,
    modules: Optional[list[str]] = None,
    plugin_dirs: Optional[list[str]] = None,
    progress: Optional[Callable[[str], None]] = None,
    cve_min_severity: Optional[str] = None,
    allow_private_targets: bool = True,
) -> ScanResult:
    def report(message: str):
        if progress:
            progress(message)

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    report(f"starting request to {url}")

    headers_to_send = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
    }

    result = ScanResult(url=url, final_url=url, status_code=0, response_time_ms=0)
    plan = build_recon_plan(modules)

    try:
        t0 = time.time()
        with httpx.Client(timeout=timeout, follow_redirects=follow_redirects, verify=False) as client:
            resp = _get_with_redirect_policy(
                client, url, headers_to_send, timeout, follow_redirects, allow_private_targets
            )
        result.response_time_ms = round((time.time() - t0) * 1000, 1)
        result.final_url = str(resp.url)
        result.status_code = resp.status_code

        resp_headers = dict(resp.headers)
        result.headers = resp_headers
        result.server = resp_headers.get("server", resp_headers.get("Server", ""))

        cookies = {k: v for k, v in resp.cookies.items()}
        body = resp.text

        report(f"response received {result.status_code}")
        parsed = urlparse(result.final_url)
        hostname = parsed.hostname or hostname
        result.technologies = run_fingerprints(
            resp_headers,
            cookies,
            body,
            url=result.final_url,
            progress=progress,
            sources={"headers"} if plan.get("headers") and not plan.get("tech") else None,
        )
        result.notes = detect_contradictions(result.technologies)
        if "cve" in (modules or []) or "cves" in (modules or []):
            _correlate_detection_cves(result.technologies, min_severity=cve_min_severity)

    except httpx.ConnectError:
        # Try HTTP fallback
        try:
            http_url = url.replace("https://", "http://")
            t0 = time.time()
            with httpx.Client(timeout=timeout, follow_redirects=follow_redirects) as client:
                resp = _get_with_redirect_policy(
                    client, http_url, headers_to_send, timeout, follow_redirects, allow_private_targets
                )
            result.response_time_ms = round((time.time() - t0) * 1000, 1)
            result.final_url = str(resp.url)
            result.status_code = resp.status_code
            resp_headers = dict(resp.headers)
            result.headers = resp_headers
            result.server = resp_headers.get("server", "")
            cookies = {k: v for k, v in resp.cookies.items()}
            body = resp.text
            report(f"response received {result.status_code}")
            parsed = urlparse(result.final_url)
            hostname = parsed.hostname or hostname
            result.technologies = run_fingerprints(
                resp_headers,
                cookies,
                body,
                url=result.final_url,
                progress=progress,
                sources={"headers"} if plan.get("headers") and not plan.get("tech") else None,
            )
            result.notes = detect_contradictions(result.technologies)
            if "cve" in (modules or []) or "cves" in (modules or []):
                _correlate_detection_cves(result.technologies, min_severity=cve_min_severity)
        except Exception as e:
            report(f"http error: {e}")
            result.error = str(e)
            return result
    except Exception as e:
        report(f"request error: {e}")
        result.error = str(e)
        return result

    result.ip = _resolve_ip(hostname)
    result.enriched = {
        "services": build_service_summary(result),
        "recon": build_recon_summary(result),
        "service_hints": [
            item for item in build_recon_summary(result) if item.get("service_hints")
        ],
    }

    if plan.get("headers"):
        result.enriched["headers"] = dict(result.headers)

    recon_results = {}
    tasks = []
    if plan.get("dns") and dns and hostname:
        tasks.append(("dns", lambda: _get_dns(hostname)))
    if plan.get("ssl") and hostname and ((ssl_check and parsed.scheme == "https") or result.final_url.startswith("https")):
        final_parsed = urlparse(result.final_url)
        tasks.append(("ssl", lambda: _get_ssl_info(final_parsed.hostname or hostname)))
    if plan.get("whois") and hostname:
        tasks.append(("whois", lambda: _get_whois(hostname)))
    if plan.get("mail") and hostname:
        tasks.append(("mail", lambda: _get_mail_records(hostname)))
    if plan.get("subdomains") and hostname:
        tasks.append(("subdomains", lambda: discover_subdomains(hostname)))
    if plan.get("ports") and hostname:
        tasks.append(("ports", lambda: _scan_common_ports(hostname, timeout=max(1, min(3, timeout // 4)))))
    if plan.get("extra") and hostname:
        tasks.append(("extra", lambda: ({
            "directories": _enumerate_directories(result.final_url, result.headers, body, timeout=max(1, min(2, timeout // 4))),
            "intel": _fetch_public_intel(hostname, body),
        })))

    if progress and tasks:
        report(f"enqueueing {len(tasks)} recon tasks")

    if progress and tasks:
        for label, _ in tasks:
            report(f"running {label} module")

    if tasks:
        with ThreadPoolExecutor(max_workers=min(6, len(tasks))) as executor:
            futures = {executor.submit(fn): name for name, fn in tasks}
            for future in as_completed(futures):
                label = futures[future]
                try:
                    recon_results[label] = future.result(timeout=3)
                except Exception:
                    recon_results[label] = None

    if plan.get("dns") and dns and hostname:
        result.dns_records = recon_results.get("dns") or {}

    if plan.get("ssl") and hostname and ((ssl_check and parsed.scheme == "https") or result.final_url.startswith("https")):
        result.ssl_info = recon_results.get("ssl") or {}

    if plan.get("whois") and hostname:
        result.whois_info = recon_results.get("whois") or {}
        result.whois_summary = summarize_whois_details(result.whois_info)

    if plan.get("mail") and hostname:
        result.mail_records = recon_results.get("mail") or []

    if plan.get("subdomains") and hostname:
        result.subdomains = recon_results.get("subdomains") or []

    if plan.get("ports") and hostname:
        result.open_ports = recon_results.get("ports") or []

    if plan.get("extra") and hostname:
        extra_payload = recon_results.get("extra") or {}
        result.directories = extra_payload.get("directories") or []
        result.extra_intel = extra_payload.get("intel") or {}
        result.extra_intel.setdefault("directories", result.directories)

    if hostname:
        external = _enrich_with_external_services(hostname, [tech.name for tech in result.technologies], api_key)
        if external:
            result.enriched.update(external)

    company_intel = _collect_company_intel(hostname, body, result.headers)
    if company_intel:
        result.extra_intel.setdefault("company", {})
        result.extra_intel["company"].update(company_intel)
        result.enriched.setdefault("company", company_intel)

    from core.plugins import run_plugins
    plugin_results = run_plugins(result, plugin_dirs, progress)
    if plugin_results:
        result.enriched["plugins"] = plugin_results

    return result
