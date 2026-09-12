# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Thin, defensive wrappers around external recon tools.

This module deliberately does NOT reimplement subdomain enumeration, port
scanning, vulnerability templates, or URL archive mining in Python - those
problems are already solved well by dedicated tools (subfinder, naabu,
nmap, nuclei, gau, waybackurls, katana, gowitness). Reimplementing them
badly would make Inoue worse at all of them. Instead:

  - If a tool is installed (found via `shutil.which`), we shell out to it,
    parse its real output, and normalize it into plain dicts/lists.
  - If a tool is NOT installed, every function returns a consistent
    envelope with `available: False` and an install hint - callers never
    get a crash or a silently-empty result they can mistake for "scanned,
    found nothing".
  - Every call is wrapped in a hard subprocess timeout. A hung external
    tool can never hang a scan.
  - We only ever pass the already-validated target as an argument (never
    through a shell), so there is no command-injection surface here.

This follows the same optional-dependency pattern already used for TLS
fingerprinting (`core/tls_fingerprint.py`) and favicon hashing
(`core/favicon.py`): the tool works identically without any of these
binaries installed, just with reduced coverage.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional


def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def _run(cmd: list[str], timeout: int) -> tuple[int, str, str]:
    """Run a command with a hard timeout. Never raises on tool failure."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", "binary not found"
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc)


def _envelope(tool: str, available: bool, results=None, error: Optional[str] = None, note: Optional[str] = None) -> dict:
    return {
        "tool": tool,
        "available": available,
        "results": results if results is not None else [],
        "error": error,
        "note": note,
    }


def _install_hint(tool: str, url: str) -> str:
    return f"{tool} not found on PATH. Install it from {url} to enable this check."


# --------------------------------------------------------------------------
# Active subdomain enumeration (subfinder)
# --------------------------------------------------------------------------

def run_subfinder(domain: str, timeout: int = 90) -> dict:
    tool = "subfinder"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://github.com/projectdiscovery/subfinder"))

    code, stdout, stderr = _run(
        [binary, "-d", domain, "-silent", "-json", "-duc"], timeout=timeout,
    )
    hosts: set[str] = set()
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            host = payload.get("host")
        except json.JSONDecodeError:
            host = line  # subfinder -silent without -json prints bare hostnames
        if host:
            hosts.add(host)

    if code not in (0, -1) and not hosts:
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=sorted(hosts))


# --------------------------------------------------------------------------
# Active port/service scanning (naabu, falling back to nmap)
# --------------------------------------------------------------------------

def run_naabu(host: str, top_ports: str = "100", timeout: int = 120) -> dict:
    tool = "naabu"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://github.com/projectdiscovery/naabu"))

    code, stdout, stderr = _run(
        [binary, "-host", host, "-top-ports", top_ports, "-json", "-silent", "-duc"], timeout=timeout,
    )
    ports = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        port = payload.get("port")
        if port is not None:
            ports.append({"port": port, "ip": payload.get("ip"), "protocol": payload.get("protocol", "tcp")})

    if code not in (0, -1) and not ports:
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=ports)


def run_nmap_service_scan(host: str, ports: Optional[str] = None, timeout: int = 180) -> dict:
    """Service/version detection via nmap. Used as the fallback active port
    scanner when naabu isn't installed, and as the richer follow-up (naabu
    finds *which* ports are open fast; nmap -sV identifies *what's* on them).
    """
    tool = "nmap"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://nmap.org/download.html"))

    port_args = ["-p", ports] if ports else ["--top-ports", "100"]
    code, stdout, stderr = _run(
        [binary, "-sV", "-Pn", *port_args, "-oX", "-", host], timeout=timeout,
    )
    services = []
    try:
        root = ET.fromstring(stdout) if stdout.strip() else None
    except ET.ParseError:
        root = None

    if root is not None:
        for host_el in root.findall("host"):
            for port_el in host_el.findall("./ports/port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port_el.find("service")
                services.append({
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "service": service_el.get("name") if service_el is not None else None,
                    "product": service_el.get("product") if service_el is not None else None,
                    "version": service_el.get("version") if service_el is not None else None,
                })

    if root is None and code not in (0, -1):
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=services)


def active_port_scan(host: str, top_ports: str = "100", timeout: int = 180) -> dict:
    """Prefer naabu (fast port discovery) + nmap -sV for service ID on
    whatever naabu finds; fall back to nmap alone for everything if naabu
    isn't installed.
    """
    naabu_result = run_naabu(host, top_ports=top_ports, timeout=timeout)
    if naabu_result["available"] and naabu_result["results"]:
        open_ports = ",".join(str(p["port"]) for p in naabu_result["results"])
        nmap_result = run_nmap_service_scan(host, ports=open_ports, timeout=timeout)
        return {"discovery": naabu_result, "services": nmap_result}

    if naabu_result["available"]:
        # naabu ran but found nothing (or errored) - no point running nmap
        # against an unknown port list, but still report nmap's availability.
        nmap_only = run_nmap_service_scan(host, timeout=timeout) if not naabu_result["results"] else naabu_result
        return {"discovery": naabu_result, "services": nmap_only}

    # naabu missing entirely - nmap does double duty as discovery+service ID.
    nmap_result = run_nmap_service_scan(host, timeout=timeout)
    return {"discovery": nmap_result, "services": nmap_result}


# --------------------------------------------------------------------------
# Vulnerability template scanning (nuclei) - "auto-run", not just export
# --------------------------------------------------------------------------

def run_nuclei(url: str, severity: Optional[str] = None, tags: Optional[str] = None, timeout: int = 300) -> dict:
    tool = "nuclei"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://github.com/projectdiscovery/nuclei"))

    cmd = [binary, "-u", url, "-jsonl", "-silent", "-duc", "-ni"]  # -ni: no interactsh (keep this passive/offline-friendly)
    if severity:
        cmd += ["-severity", severity]
    if tags:
        cmd += ["-tags", tags]

    code, stdout, stderr = _run(cmd, timeout=timeout)
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = payload.get("info", {})
        findings.append({
            "template_id": payload.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "matched_at": payload.get("matched-at"),
            "description": info.get("description"),
        })

    if code not in (0, -1) and not findings:
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=findings)


# --------------------------------------------------------------------------
# JS/URL harvesting (gau, waybackurls, katana) - merged into one signal
# --------------------------------------------------------------------------

def run_gau(domain: str, timeout: int = 120) -> dict:
    tool = "gau"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://github.com/lc/gau"))
    code, stdout, stderr = _run([binary, domain, "--subs"], timeout=timeout)
    urls = [line.strip() for line in stdout.splitlines() if line.strip()]
    if code not in (0, -1) and not urls:
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=urls)


def run_waybackurls(domain: str, timeout: int = 120) -> dict:
    tool = "waybackurls"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://github.com/tomnomnom/waybackurls"))
    code, stdout, stderr = _run([binary, domain], timeout=timeout)
    urls = [line.strip() for line in stdout.splitlines() if line.strip()]
    if code not in (0, -1) and not urls:
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=urls)


def run_katana(url: str, depth: int = 2, timeout: int = 120) -> dict:
    tool = "katana"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://github.com/projectdiscovery/katana"))
    code, stdout, stderr = _run(
        [binary, "-u", url, "-silent", "-jc", "-duc", "-depth", str(depth)], timeout=timeout,
    )
    urls = [line.strip() for line in stdout.splitlines() if line.strip()]
    if code not in (0, -1) and not urls:
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=urls)


def harvest_urls(domain: str, url: str, timeout: int = 120) -> dict:
    """Run gau + waybackurls + katana and merge into one deduplicated list.

    gau/waybackurls mine archive.org + common crawl + OTX (historical URLs,
    including ones no longer linked from the live site - great for finding
    old/forgotten endpoints). katana live-crawls the current site (catches
    what archives miss). Together they cover both angles.
    """
    gau_result = run_gau(domain, timeout=timeout)
    wayback_result = run_waybackurls(domain, timeout=timeout)
    katana_result = run_katana(url, timeout=timeout)

    merged: set[str] = set()
    for source in (gau_result, wayback_result, katana_result):
        merged.update(source.get("results") or [])

    return {
        "gau": gau_result,
        "waybackurls": wayback_result,
        "katana": katana_result,
        "merged_urls": sorted(merged),
        "merged_count": len(merged),
    }


# --------------------------------------------------------------------------
# Screenshots (gowitness) - useful for fast visual triage of large scope
# --------------------------------------------------------------------------

def run_gowitness(url: str, output_dir: str, timeout: int = 60) -> dict:
    """Capture a screenshot via gowitness.

    NOTE: gowitness requires a Chrome/Chromium runtime in addition to the
    gowitness binary itself; both must be present. If either is missing,
    this degrades gracefully like every other wrapper here rather than
    raising. gowitness v3's CLI is `gowitness scan single` - if you're on
    an older v2 install, update it or adjust this command accordingly.
    """
    tool = "gowitness"
    binary = _which(tool)
    if not binary:
        return _envelope(tool, False, note=_install_hint(tool, "https://github.com/sensepost/gowitness"))

    code, stdout, stderr = _run(
        [binary, "scan", "single", "--url", url, "--screenshot-path", output_dir], timeout=timeout,
    )
    if code not in (0, -1):
        return _envelope(tool, True, error=stderr.strip()[:500] or f"exit code {code}")
    return _envelope(tool, True, results=[{"output_dir": output_dir, "stdout": stdout.strip()[:500]}])
