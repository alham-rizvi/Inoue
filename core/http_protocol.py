# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
HTTP protocol capability detection.

Which HTTP version a site can actually speak is worth recording because the
older versions leave performance and some request-smuggling defenses on the
table. The signal comes from two independent places and they mean different
things:

  * the `alt-svc` header, which is the server *advertising* that an
    alternative protocol is reachable on some other endpoint (typically
    h3 for HTTP/3 over QUIC, h2 for HTTP/2). Advertising is not proof the
    protocol is actually served, so it is recorded as advertised-only.
  * one real request (only when a URL is supplied), whose negotiated
    `http_version` is the ground truth for *this* client, on *this* network
    path, for *this* hostname - not a property of the site as a whole.

False-positive limits, stated plainly: absence of an `alt-svc` header says
nothing about whether the server supports HTTP/2 or HTTP/3, because the
header is optional and many servers that speak HTTP/2 never advertise
HTTP/3. That is why the protocol fields are tri-state - True when the header
advertises it, False when the header is present but omits it, and None when
there is no header to read (unknown, not "no"). This module never sets a
field to False on the strength of a missing header. Likewise a single
HTTP/1.1 negotiation can be caused by a proxy, a CDN edge, or a client
without HTTP/2 support, so an observed version is reported as fact for the
request that was made and is never upgraded into a claim about the host.
"""

from __future__ import annotations

import httpx

# A fixed, ordinary browser User-Agent. Identical to the one used elsewhere in
# Inoue so the scan presents one consistent fingerprint to every target.
_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"

# Advertise the encodings we can actually decode so a live request reports the
# negotiated compression rather than a guess.
_ACCEPT_ENCODING = "gzip, deflate, br, zstd"

# Content types where the absence of compression is worth an advisory note.
# Binary media is routinely served uncompressed on purpose and must not be
# flagged.
_TEXTY = ("text/", "application/json", "application/javascript", "application/xml", "application/xhtml")


def _parse_alt_svc(value: str) -> tuple[bool, bool, list[str]]:
    """Parse an alt-svc header into (http2_advertised, http3_advertised, protocols).

    Format is a comma-separated list of `protocol-id="host:port"; params`, e.g.
    `h3=":443"; ma=86400, h2=":443"`. The special value `clear` means the server
    is withdrawing its alternatives, which is a determination that neither
    protocol is currently advertised rather than an absence of information.
    """
    protocols: list[str] = []
    for entry in (value or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        protocol_id = entry.split(";")[0].split("=")[0].strip().lower()
        if protocol_id:
            protocols.append(protocol_id)

    http3 = any(p.startswith("h3") for p in protocols)  # h3, h3-29, h3-32, ...
    http2 = any(p == "h2" for p in protocols)
    return http2, http3, protocols


def analyze(headers: dict, url: str = "", timeout: int = 5) -> dict:
    """Report the HTTP protocol capabilities of a host.

    `headers` is a response-header mapping already fetched by the caller (used
    for the passive parts of the analysis). `url`, when supplied, triggers a
    single live request to read the actually negotiated HTTP version, TLS
    protocol and content encoding. Nothing here raises: any network problem is
    recorded in `errors` and the partial result is still returned.
    """
    result: dict = {
        "http_version": None,
        "http2": None,
        "http3": None,
        "alt_svc": None,
        "compression": [],
        "server_timing": False,
        "tls_protocol": None,
        "issues": [],
        "errors": [],
    }

    lowered = {k.lower(): v for k, v in (headers or {}).items()}

    # --- passive: alt-svc -------------------------------------------------
    alt_svc = lowered.get("alt-svc")
    if alt_svc is not None:
        alt_svc = alt_svc.strip()
        result["alt_svc"] = alt_svc or None
        is_clear = alt_svc.lower() == "clear"
        if is_clear:
            # Explicit withdrawal: a determination, not an assumption.
            result["http2"] = False
            result["http3"] = False
        else:
            http2, http3, _protocols = _parse_alt_svc(alt_svc)
            result["http2"] = http2
            result["http3"] = http3
    # No header at all -> leave both as None (unknown, not "no").

    # --- passive: compression / server-timing -----------------------------
    content_encoding = lowered.get("content-encoding", "")
    result["compression"] = [
        enc.strip().lower() for enc in content_encoding.split(",") if enc.strip()
    ]
    result["server_timing"] = bool((lowered.get("server-timing") or "").strip())

    if not url:
        return result

    # --- live: one request -------------------------------------------------
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    body_length = 0
    content_type = ""
    try:
        with httpx.Client(timeout=max(1, timeout), verify=False, follow_redirects=True) as client:
            response = client.get(
                url,
                headers={"User-Agent": _USER_AGENT, "Accept-Encoding": _ACCEPT_ENCODING},
            )
        result["http_version"] = response.http_version

        # An observed HTTP/2 negotiation is stronger evidence than a header, so
        # it may promote http2 to True. It is deliberately NOT used to set
        # http2 to False: a single HTTP/1.1 result can come from the client,
        # the proxy or the CDN edge rather than the origin's real capability.
        if (response.http_version or "").startswith("HTTP/2"):
            result["http2"] = True

        live_encoding = response.headers.get("content-encoding", "")
        live_encodings = [e.strip().lower() for e in live_encoding.split(",") if e.strip()]
        for enc in live_encodings:
            if enc not in result["compression"]:
                result["compression"].append(enc)
        if "server-timing" in {k.lower() for k in response.headers}:
            result["server_timing"] = True

        content_type = response.headers.get("content-type", "")
        try:
            body_length = len(response.content or b"")
        except Exception:
            body_length = 0

        # Best-effort TLS protocol extraction. httpx exposes no public attribute
        # for this and the socket is already closed by the time we look, so None
        # here simply means "not available", not "no TLS".
        try:
            network_stream = response.extensions.get("network_stream")
            ssl_object = network_stream.get_extra_info("ssl_object") if network_stream else None
            if ssl_object is not None:
                result["tls_protocol"] = ssl_object.version()
        except Exception:
            result["tls_protocol"] = None
    except Exception as exc:
        result["errors"].append(f"live request to {url} failed: {exc}")
        return result

    # --- advisory issues ---------------------------------------------------
    if scheme == "https" and result["http2"] is not True and (result["http_version"] in (None, "HTTP/1.1")):
        result["issues"].append(
            "HTTP/2 is not offered on this HTTPS endpoint (negotiated "
            f"{result['http_version'] or 'unknown'}); enabling it is a low-cost "
            "performance and robustness improvement."
        )
    if not result["compression"] and _is_textual(content_type) and body_length > 512:
        result["issues"].append(
            "No content compression observed on a text response "
            f"({body_length} bytes); enabling gzip/br would reduce transfer size."
        )

    return result


def _is_textual(content_type: str) -> bool:
    """True when a content type is one where compression is normally expected."""
    lowered = (content_type or "").lower()
    return any(lowered.startswith(prefix) or prefix in lowered for prefix in _TEXTY)
