"""Best-effort TLS fingerprint helpers.

This module intentionally degrades gracefully when optional dependencies or
handshakes are unavailable. It is informational only and never weakens TLS
verification for fixed third-party services.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from typing import Any

KNOWN_TLS_FINGERPRINTS: dict[str, dict[str, str]] = {
    "cloudflare": {
        "TLS_AES_256_GCM_SHA384|TLSv1.3": "cloudflare-1",
        "TLS_CHACHA20_POLY1305_SHA256|TLSv1.3": "cloudflare-2",
    },
    "akamai": {
        "TLS_AES_256_GCM_SHA384|TLSv1.3": "akamai-1",
    },
    "fastly": {
        "TLS_AES_256_GCM_SHA384|TLSv1.3": "fastly-1",
    },
    "netlify": {
        "TLS_AES_256_GCM_SHA384|TLSv1.3": "netlify-1",
    },
}


def known_tls_fingerprints() -> dict[str, dict[str, str]]:
    return dict(KNOWN_TLS_FINGERPRINTS)


def fingerprint_tls(service: str, cipher: str = "", protocol: str = "") -> str:
    """Return a stable fingerprint string for a service or TLS stack.

    Known CDN/WAF fingerprints are keyed by service name to keep intentionally
    recognizable, reviewable values without depending on an external library.
    """
    service_name = (service or "custom").strip().lower()
    if not cipher and not protocol:
        return service_name or "unknown"

    key = f"{cipher or 'unknown'}|{protocol or 'unknown'}"
    match = KNOWN_TLS_FINGERPRINTS.get(service_name, {}).get(key)
    if match:
        return match

    material = f"{service_name}|{cipher}|{protocol}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:12]
    return f"{service_name}-{digest}"


def extract_tls_metadata(hostname: str, port: int = 443, timeout: int = 5) -> dict[str, Any]:
    """Perform a best-effort TLS handshake and collect metadata."""
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher = tls_sock.cipher()
                protocol = tls_sock.version()
                metadata = {
                    "available": True,
                    "hostname": hostname,
                    "port": port,
                    "cipher": cipher[0] if cipher else "",
                    "protocol": protocol or "",
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "not_after": cert.get("notAfter", "") if cert else "",
                    "not_before": cert.get("notBefore", "") if cert else "",
                }
                metadata["fingerprint"] = fingerprint_tls(
                    service=(metadata["issuer"].get("organizationName") or hostname).lower(),
                    cipher=metadata["cipher"],
                    protocol=metadata["protocol"],
                )
                return metadata
    except Exception as exc:  # pragma: no cover - best effort only
        return {
            "available": False,
            "hostname": hostname,
            "port": port,
            "error": str(exc),
            "fingerprint": "",
        }
