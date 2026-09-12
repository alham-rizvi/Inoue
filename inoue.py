#!/usr/bin/env python3
# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Inoue - tech stack fingerprinting CLI
Author: Alham Rizvi
Repository: https://github.com/alhamrizvi-cloud/Inoue
"""

import json
import asyncio
import concurrent.futures
import html
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Callable, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.cve import refresh_cve_dataset
from core.config import load_config
from core.scanner import build_service_summary, scan, scan_many, ScanResult
from core.terminal import TerminalSettings, create_console, load_terminal_settings

app = typer.Typer(help="Inoue — tech stack fingerprinting CLI", add_completion=False)
terminal_settings = TerminalSettings()
console = create_console(terminal_settings)


def load_app_version() -> str:
    project_file = Path(__file__).resolve().parent / "pyproject.toml"
    if project_file.exists():
        text = project_file.read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
        if match:
            return match.group(1).strip()
    return "1.0.1"


APP_VERSION = load_app_version()

CATEGORY_COLORS = {
    "Web Server":       "cyan",
    "Language":         "green",
    "Framework":        "bright_green",
    "CMS":              "yellow",
    "CMS / E-Commerce": "yellow",
    "Site Builder":     "yellow",
    "JS Framework":     "bright_blue",
    "JS Library":       "blue",
    "CSS Framework":    "magenta",
    "CDN / Security":   "red",
    "CDN":              "bright_red",
    "WAF":              "bright_red",
    "Cache":            "orange3",
    "Analytics":        "purple",
    "Security Header":  "green",
    "Database":         "bright_cyan",
    "Search Engine":    "bright_cyan",
    "Hosting":          "bright_blue",
    "Payment":          "bright_yellow",
    "UI Library":       "bright_magenta",
    "Security":         "bright_green",
    "CRM / Chat":       "bright_white",
    "Other":            "white",
}


def print_banner():
    console.print(r"""[bold white]    _                      
   (_)___  ____  __  _____ 
  / / __ \/ __ \/ / / / _ \
 / / / / / /_/ / /_/ /  __/
/_/_/ /_/\____/\__,_/\___/ """ + f"[/bold white][dim]v{APP_VERSION}  tech stack\nfingerprinting[/dim]\n")


def emit_cli_error(message: str, *, detail: Optional[str] = None, hint: Optional[str] = None, exit_code: int = 1) -> None:
    console.print(f"[red]error[/red] {message}")
    if detail:
        console.print(f"  [dim]{detail}[/dim]")
    if hint:
        console.print(f"  [yellow]hint[/yellow] {hint}")
    raise typer.Exit(exit_code)


def render_result(result: ScanResult, verbose: bool = False, evidence: bool = False, modules: Optional[list[str]] = None):
    selected_modules = {item.lower() for item in (modules or [])}
    show_module = lambda name: verbose or name in selected_modules or "all" in selected_modules or "full-recon" in selected_modules
    status_color = "green" if result.status_code < 300 else "yellow" if result.status_code < 400 else "red"

    console.print(f"  [dim]url[/dim]     {result.final_url}")
    if getattr(result, "cache_hit", False):
        console.print("  [yellow]cache[/yellow]  hit from local cache")
    console.print(f"  [dim]ip[/dim]      [cyan]{result.ip or 'unknown'}[/cyan]")
    console.print(f"  [dim]status[/dim]  [{status_color}]{result.status_code}[/{status_color}]  [dim]{result.response_time_ms}ms[/dim]")
    if result.server:
        console.print(f"  [dim]server[/dim]  {result.server}")
    console.print()

    service_summary = build_service_summary(result)
    if service_summary:
        by_category = defaultdict(list)
        for t in result.technologies:
            by_category[t.category].append(t)

        geometry = terminal_settings.table_geometry
        table = Table(box=None, show_header=True, header_style="dim", padding=geometry["padding"], show_edge=False)
        table.add_column("category", width=geometry["category"])
        table.add_column("technology", width=geometry["technology"])
        table.add_column("version", width=geometry["version"])
        table.add_column("confidence", width=12)
        if evidence:
            table.add_column("evidence", width=55)

        for category in sorted(by_category.keys()):
            techs = by_category[category]
            color = terminal_settings.colors.get(category, CATEGORY_COLORS.get(category, "white"))
            for i, t in enumerate(techs):
                cat_label = f"[dim]{category}[/dim]" if i == 0 else ""
                ver_label = f"[dim]{t.version or 'unknown'}[/dim]"
                conf_label = f"[dim]{t.confidence}[/dim]"
                row = [cat_label, f"[{color}]{t.name}[/{color}]", ver_label, conf_label]
                if evidence:
                    row.append(f"[dim]{t.evidence[:70]}[/dim]" if t.evidence else "")
                table.add_row(*row)

        console.print(table)
        console.print(f"\n  [dim]{len(service_summary)} services detected[/dim]\n")
        cve_matches = [(tech.name, cve) for tech in result.technologies for cve in tech.cves]
        if cve_matches:
            console.print("  [red]── known CVEs ──────────────────────────[/red]")
            for tech_name, cve in cve_matches:
                console.print(f"  [red]{cve['id']}[/red] {tech_name} [{cve['severity']}] {cve['summary']}")
            console.print()
    else:
        console.print("  [dim]no technologies detected[/dim]\n")

    if verbose and result.enriched:
        console.print("  [dim]── recon ─────────────────────────────[/dim]")
        services = result.enriched.get("services", [])
        service_hints = result.enriched.get("service_hints", [])
        if services:
            console.print("  [cyan]services[/cyan]")
            for item in services[:10]:
                console.print(f"    - {item['name']} {item['version']} [{item['category']}]")
        if service_hints:
            console.print("  [yellow]service hints[/yellow]")
            for item in service_hints[:10]:
                console.print(f"    - {item['name']} -> {', '.join(item['service_hints'])}")
        if not services and not service_hints:
            console.print("  [dim]no enrichment data[/dim]")
        console.print()

    if result.whois_info and verbose:
        console.print("  [dim]── whois ─────────────────────────────[/dim]")
        if result.whois_summary:
            for key in ["domain", "company", "registrant", "country", "registrar", "creation_date", "expiration_date"]:
                value = result.whois_summary.get(key)
                if value:
                    console.print(f"  [cyan]{key}[/cyan] {value}")
            if result.whois_summary.get("nameservers"):
                console.print(f"  [cyan]nameservers[/cyan] {', '.join(result.whois_summary['nameservers'][:6])}")
        else:
            for key, value in result.whois_info.items():
                if isinstance(value, list):
                    console.print(f"  [cyan]{key}[/cyan] {', '.join(str(v) for v in value[:5])}")
                else:
                    console.print(f"  [cyan]{key}[/cyan] {value}")
        console.print()

    if result.mail_records and show_module("mail"):
        console.print("  [dim]── mail records ─────────────────────[/dim]")
        for item in result.mail_records:
            console.print(f"  [cyan]MX[/cyan] {item}")
        console.print()

    if result.subdomains and show_module("subdomains"):
        console.print("  [dim]── subdomains ───────────────────────[/dim]")
        for item in result.subdomains[:12]:
            console.print(f"  [cyan]sub[/cyan] {item}")
        if len(result.subdomains) > 12:
            console.print(f"  [dim]+{len(result.subdomains) - 12} more[/dim]")
        console.print()

    if result.directories and show_module("extra"):
        console.print("  [dim]── directories ───────────────────────[/dim]")
        for item in result.directories[:10]:
            console.print(f"  [cyan]{item['source']}[/cyan] {item['path']} -> {item['status_code']}")
        console.print()

    if result.open_ports and show_module("ports"):
        console.print("  [dim]── open ports ────────────────────────[/dim]")
        for item in result.open_ports:
            service = item.get("service", "unknown") if isinstance(item, dict) else "unknown"
            port = item.get("port", "?") if isinstance(item, dict) else item
            console.print(f"  [cyan]{port}[/cyan] {service}")
        console.print()

    if result.whois_info and show_module("whois"):
        console.print("  [dim]── whois ─────────────────────────────[/dim]")
        summary = result.whois_summary or {}
        for key in ["domain", "company", "registrant", "country", "registrar", "creation_date", "expiration_date"]:
            value = summary.get(key)
            if value:
                console.print(f"  [cyan]{key}[/cyan] {value}")
        if summary.get("nameservers"):
            console.print(f"  [cyan]nameservers[/cyan] {', '.join(summary['nameservers'][:6])}")
        rdap = result.whois_info.get("rdap", {})
        if isinstance(rdap, dict):
            if rdap.get("status"):
                console.print(f"  [cyan]status[/cyan] {', '.join(rdap['status'][:8])}")
            if rdap.get("events"):
                for name, value in rdap["events"].items():
                    console.print(f"  [cyan]{name}[/cyan] {value}")
            for entity in rdap.get("entities", [])[:8]:
                label = ", ".join(entity.get("roles", [])) or "entity"
                identity = entity.get("org") or entity.get("fn") or entity.get("handle")
                if identity:
                    console.print(f"  [cyan]{label}[/cyan] {identity}")
            if rdap.get("url"):
                console.print(f"  [cyan]rdap source[/cyan] {rdap['url']}")
        console.print()

    if result.extra_intel and show_module("extra"):
        console.print("  [dim]── public intel ─────────────────────[/dim]")
        for key, value in result.extra_intel.items():
            if isinstance(value, list):
                console.print(f"  [cyan]{key}[/cyan] {', '.join(str(v) for v in value[:8])}")
            else:
                console.print(f"  [cyan]{key}[/cyan] {value}")
        console.print()

    if result.ssl_info and not result.ssl_info.get("error") and show_module("ssl"):
        ssl = result.ssl_info
        subject = ssl.get("subject", {})
        issuer = ssl.get("issuer", {})
        console.print("  [dim]── ssl ──────────────────────────────[/dim]")
        console.print(f"  [dim]protocol[/dim]  {ssl.get('protocol', '?')}  [dim]cipher[/dim] {ssl.get('cipher', '?')}")
        console.print(f"  [dim]issued to[/dim] {subject.get('commonName', '?')}")
        console.print(f"  [dim]issued by[/dim] {issuer.get('organizationName', '?')}")
        console.print(f"  [dim]valid[/dim]     {ssl.get('notBefore', '?')}  →  {ssl.get('notAfter', '?')}")
        if ssl.get("sslyze"):
            console.print(f"  [dim]tls detail[/dim] sslyze available: {ssl['sslyze'].get('protocols', ['?'])}")
        if ssl.get("san"):
            sans = ssl["san"][:6]
            console.print(f"  [dim]san[/dim]       {', '.join(sans)}" + (" ..." if len(ssl["san"]) > 6 else ""))
        console.print()

    if result.dns_records and show_module("dns"):
        console.print("  [dim]── dns ───────────────────────────────[/dim]")
        for rtype, values in result.dns_records.items():
            for v in values[:5]:
                console.print(f"  [cyan]{rtype:<8}[/cyan] {v}")
        console.print()

    if show_module("headers"):
        normalized_headers = {str(key).lower(): value for key, value in result.headers.items()}
        sec_headers = [
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy",
            "Permissions-Policy", "Cross-Origin-Opener-Policy",
        ]
        console.print("  [dim]── security headers ────────────────────[/dim]")
        for h in sec_headers:
            v = normalized_headers.get(h.lower(), "")
            if v:
                console.print(f"  [green]+[/green] [dim]{h}[/dim]")
            else:
                console.print(f"  [red]-[/red] [dim]{h}[/dim]")
        console.print()

    if show_module("headers"):
        console.print("  [dim]── response headers ────────────────────[/dim]")
        for k, v in result.headers.items():
            console.print(f"  [dim]{k}:[/dim] {v[:100]}")
        console.print()


def format_update_report(fetch_output: str, pull_output: str, log_output: str, latest_commit_output: str, changed_files_output: str, status_output: str) -> str:
    lines = []
    if fetch_output.strip():
        lines.append(fetch_output.strip())
    if pull_output.strip():
        lines.append(pull_output.strip())
    if log_output.strip():
        lines.append("")
        lines.append("Recent commits")
        lines.extend(f"- {entry}" for entry in log_output.strip().splitlines() if entry.strip())
    if latest_commit_output.strip():
        lines.append("")
        lines.append("Latest commit")
        lines.extend(f"- {entry}" for entry in latest_commit_output.strip().splitlines() if entry.strip())
    if changed_files_output.strip():
        lines.append("")
        lines.append("Changed files")
        lines.extend(f"- {entry}" for entry in changed_files_output.strip().splitlines() if entry.strip())
    if status_output.strip():
        lines.append("")
        lines.append(status_output.strip())
    return "\n".join(lines).strip()


def load_targets(targets: Optional[list[str]], list_file: Optional[str]) -> list[str]:
    values = list(targets or [])
    if list_file:
        values.extend(Path(list_file).read_text(encoding="utf-8").splitlines())
    elif not values and not sys.stdin.isatty():
        try:
            values.extend(sys.stdin.read().splitlines())
        except OSError:
            pass

    normalized = []
    seen = set()
    for value in values:
        target = value.strip()
        if not target or target.startswith("#") or target in seen:
            continue
        seen.add(target)
        normalized.append(target)
    return normalized


def write_nuclei_export(results: list[ScanResult], output_path: str) -> None:
    grouped: dict[str, list[str]] = {}
    for result in results:
        for technology in result.technologies:
            tag = re.sub(r"[^a-z0-9]+", "-", technology.name.lower()).strip("-")
            if not tag:
                continue
            grouped.setdefault(tag, [])
            if result.final_url not in grouped[tag]:
                grouped[tag].append(result.final_url)
    Path(output_path).write_text(json.dumps(grouped, indent=2) + "\n", encoding="utf-8")


def result_to_dict(result: ScanResult) -> dict:
    return {
        "url": result.url,
        "final_url": result.final_url,
        "ip": result.ip,
        "status_code": result.status_code,
        "response_time_ms": result.response_time_ms,
        "server": result.server,
        "headers": result.headers,
        "technologies": [
            {
                "name": technology.name,
                "category": technology.category,
                "version": technology.version,
                "confidence": technology.confidence,
                "confidence_score": technology.confidence_score,
                "evidence": technology.evidence,
                "cves": technology.cves,
            }
            for technology in result.technologies
        ],
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
        "enriched": result.enriched,
        "waf": result.waf,
        "js_intel": result.js_intel,
        "notes": result.notes,
        "error": result.error,
        "cache_hit": getattr(result, "cache_hit", False),
    }


def render_html_report(results: list[ScanResult]) -> str:
    rows = []
    cves = []
    recon_sections = []
    for result in results:
        data = result_to_dict(result)
        technologies = data["technologies"]
        recon_lines = [
            f"<strong>URL:</strong> {html.escape(data['final_url'])}",
            f"<strong>Status:</strong> {data['status_code']} ({data['response_time_ms']} ms)",
            f"<strong>IP:</strong> {html.escape(data['ip'] or 'unknown')}",
        ]
        if data["headers"]:
            recon_lines.append("<strong>Headers:</strong><br>" + "<br>".join(
                f"{html.escape(str(key))}: {html.escape(str(value))}" for key, value in data["headers"].items()
            ))
        for label, values in [
            ("DNS", data["dns"]),
            ("Subdomains", data["subdomains"]),
            ("Mail records", data["mail_records"]),
            ("Open ports", data["open_ports"]),
            ("Directories", data["directories"]),
        ]:
            if values:
                recon_lines.append(f"<strong>{label}:</strong> {html.escape(str(values))}")
        if data["whois_summary"]:
            recon_lines.append(f"<strong>WHOIS:</strong> {html.escape(str(data['whois_summary']))}")
        if data["extra_intel"]:
            recon_lines.append(f"<strong>Public intel:</strong> {html.escape(str(data['extra_intel']))}")
        recon_sections.append("<section><h3>{}</h3><p>{}</p></section>".format(
            html.escape(data["final_url"]), "<br>".join(recon_lines)
        ))
        if not technologies:
            rows.append(
                "<tr><td>{}</td><td colspan=\"4\">No technologies detected</td></tr>".format(
                    html.escape(data["final_url"]),
                )
            )
            continue
        for technology in technologies:
            rows.append(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                    html.escape(data["final_url"]),
                    html.escape(technology["name"]),
                    html.escape(technology["category"]),
                    html.escape(str(technology["version"] or "unknown")),
                    html.escape(str(technology["confidence_score"])),
                )
            )
            for cve in technology["cves"]:
                cves.append(
                    "<li><strong>{}</strong> {} ({})</li>".format(
                        html.escape(cve["id"]),
                        html.escape(technology["name"]),
                        html.escape(cve["severity"]),
                    )
                )
    cve_section = "<ul>{}</ul>".format("".join(cves)) if cves else "<p>No known CVE matches.</p>"
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Inoue report</title>
<style>body{{font:15px sans-serif;margin:2rem;color:#202124}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:.5rem;text-align:left}}th{{background:#f2f2f2}}h1{{margin-bottom:.25rem}}</style>
</head><body><h1>Inoue reconnaissance report</h1>
<table><thead><tr><th>Target</th><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th></tr></thead>
<tbody>{rows}</tbody></table><h2>Recon details</h2>{recon_sections}<h2>Known CVEs</h2>{cve_section}</body></html>
""".format(rows="".join(rows), recon_sections="".join(recon_sections), cve_section=cve_section)


def render_markdown_report(results: list[ScanResult]) -> str:
    lines = [
        "# Inoue reconnaissance report",
        "",
        "| Target | Technology | Category | Version | Confidence | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for result in results:
        if not result.technologies:
            lines.append(f"| {result.final_url} | — | — | — | — | no technologies detected |")
            continue
        for technology in result.technologies:
            evidence = (technology.evidence or "—").replace("\n", " ")[:120]
            lines.append(
                f"| {result.final_url} | {technology.name} | {technology.category} | {technology.version or 'unknown'} | {technology.confidence} | {evidence} |"
            )
        lines.extend([
            "",
            f"## Recon details: {result.final_url}",
            "",
            f"- Status: {result.status_code} ({result.response_time_ms} ms)",
            f"- IP: {result.ip or 'unknown'}",
        ])
        if result.headers:
            lines.append(f"- Headers: {result.headers}")
        if result.dns_records:
            lines.append(f"- DNS: {result.dns_records}")
        if result.whois_summary:
            lines.append(f"- WHOIS: {result.whois_summary}")
        if result.subdomains:
            lines.append(f"- Subdomains: {result.subdomains}")
        if result.mail_records:
            lines.append(f"- Mail records: {result.mail_records}")
        if result.open_ports:
            lines.append(f"- Open ports: {result.open_ports}")
        if result.directories:
            lines.append(f"- Directories: {result.directories}")
        if result.extra_intel:
            lines.append(f"- Public intel: {result.extra_intel}")

    if not results:
        lines.append("No results.")
    return "\n".join(lines)


def result_exit_code(results: list[ScanResult], cve_enabled: bool, fail_on_cve: bool) -> int:
    if any(result.error for result in results):
        return 1
    if cve_enabled and fail_on_cve and any(technology.cves for result in results for technology in result.technologies):
        return 2
    return 0


def run_self_update() -> dict:
    repo_root = Path(__file__).resolve().parent
    try:
        fetch = subprocess.run(["git", "-C", str(repo_root), "fetch", "--all", "--prune"], capture_output=True, text=True)
        pull = subprocess.run(["git", "-C", str(repo_root), "pull", "--ff-only"], capture_output=True, text=True)
        status = subprocess.run(["git", "-C", str(repo_root), "status", "--short"], capture_output=True, text=True)
        recent_log = subprocess.run(["git", "-C", str(repo_root), "log", "--pretty=format:%h %s", "-5"], capture_output=True, text=True)
        latest_commit = subprocess.run(["git", "-C", str(repo_root), "show", "--stat", "--oneline", "--decorate", "--no-renames", "HEAD"], capture_output=True, text=True)
        changed_files = subprocess.run(["git", "-C", str(repo_root), "show", "--name-only", "--pretty=format:", "HEAD"], capture_output=True, text=True)
        report = format_update_report(
            fetch_output=fetch.stdout + fetch.stderr,
            pull_output=pull.stdout + pull.stderr,
            log_output=recent_log.stdout,
            latest_commit_output=latest_commit.stdout,
            changed_files_output=changed_files.stdout,
            status_output=status.stdout,
        )
        ok = fetch.returncode == 0 and pull.returncode == 0
        return {
            "ok": ok,
            "message": "Repository updated successfully" if ok else "Update failed",
            "details": report,
        }
    except Exception as exc:
        return {"ok": False, "message": str(exc), "details": "Unable to retrieve update details."}


@app.command()
def update():
    """Fetch the latest catalog and scanner changes from the repository."""
    result = run_self_update()
    if result["ok"]:
        console.print(f"[green]updated[/green] {result['message']}")
    else:
        console.print(f"[red]update failed[/red] {result['message']}")

    if result.get("details"):
        console.print()
        console.print(result["details"])


@app.command()
def about():
    """Show project metadata and quick usage hints."""
    console.print(f"[bold]Inoue[/bold] [dim]v{APP_VERSION}[/dim]")
    console.print("Repository: https://github.com/alhamrizvi-cloud/Inoue")
    console.print("Presets: fast, full-recon, all")
    console.print("Examples:")
    console.print("  - inoue -m fast https://target.example")
    console.print("  - inoue -m full-recon https://target.example")
    console.print("  - inoue --json -o report.json https://target.example")


@app.command("update-cve")
def update_cve(
    source_url: Optional[str] = typer.Option(None, "--source-url", help="Override the NVD JSON feed URL"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Write the refreshed dataset to FILE"),
):
    """Refresh the local offline CVE awareness dataset."""
    try:
        count = refresh_cve_dataset(source_url=source_url, output_path=output)
        console.print(f"[green]updated[/green] CVE dataset with {count} entries")
    except Exception as exc:
        console.print(f"[red]update-cve failed[/red] {exc}")
        raise typer.Exit(1)


def run_history_command(
    target: str,
    history_path: Optional[str] = None,
    limit: int = 20,
    json_out: bool = False,
):
    """Show how a target's tech stack, CVEs, ports, and certificate changed across saved scans.

    Snapshots are only recorded when a scan is run with --save-history, so
    run a few scans over time before expecting a timeline here.
    """
    from core.history import DEFAULT_HISTORY_PATH, build_timeline, list_snapshots

    db_path = history_path or DEFAULT_HISTORY_PATH
    normalized_target = target if target.startswith(("http://", "https://")) else f"https://{target}"
    snapshots = list_snapshots(db_path, normalized_target, limit=limit)

    if not snapshots:
        if json_out:
            print(json.dumps({"target": normalized_target, "snapshots": 0, "timeline": []}))
        else:
            console.print(f"[yellow]no saved history[/yellow] for {normalized_target}")
            console.print("  Run scans with [bold]--save-history[/bold] to start building a timeline.")
        return

    timeline = build_timeline(db_path, normalized_target, limit=limit)

    if json_out:
        print(json.dumps({"target": normalized_target, "snapshots": len(snapshots), "timeline": timeline}, indent=2))
        return

    console.print(f"[bold]{normalized_target}[/bold] — {len(snapshots)} saved snapshot(s)")
    if not timeline:
        console.print("  Only one snapshot saved so far; run another scan with --save-history to see changes.")
        return

    from datetime import datetime, timezone
    for entry in timeline:
        from_ts = datetime.fromtimestamp(entry["from"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        to_ts = datetime.fromtimestamp(entry["to"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        console.print(f"\n[dim]{from_ts}[/dim] → [dim]{to_ts}[/dim]")
        diff = entry["diff"]
        if not any(diff.values()):
            console.print("  no changes")
            continue
        for change in diff.get("technology_changes", []):
            if change["status"] == "added":
                console.print(f"  [green]+ {change['name']}[/green] {change.get('version') or ''}")
            elif change["status"] == "removed":
                console.print(f"  [red]- {change['name']}[/red] {change.get('version') or ''}")
            else:
                console.print(f"  [yellow]~ {change['name']}[/yellow] {change.get('previous')} → {change.get('current')}")
        for change in diff.get("cve_changes", []):
            marker = "green" if change["status"] == "added" else "dim"
            console.print(f"  [{marker}]CVE {change['status']}: {change['id']}[/{marker}]")
        ports = diff.get("port_changes", {})
        if ports.get("added"):
            console.print(f"  [green]ports opened:[/green] {ports['added']}")
        if ports.get("removed"):
            console.print(f"  [red]ports closed:[/red] {ports['removed']}")
        for cert in diff.get("certificate_expiry", []):
            console.print(f"  [yellow]certificate expiring in {cert['days_remaining']}d[/yellow] ({cert['expires']})")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    targets: Optional[list[str]] = typer.Argument(None, help="Target URLs or IPs (e.g. example.com, 10.10.11.2)"),
    list_file: Optional[str] = typer.Option(None, "-l", "--list", help="Read one target per line from FILE"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show SSL, DNS, security headers, all headers"),
    evidence: bool = typer.Option(False, "-e", "--evidence", help="Show detection evidence"),
    no_dns: bool = typer.Option(False, "--no-dns", help="Skip DNS enumeration"),
    no_ssl: bool = typer.Option(False, "--no-ssl", help="Skip SSL inspection"),
    tls_fingerprint: bool = typer.Option(False, "--tls-fingerprint", help="Capture best-effort TLS metadata and fingerprint when available"),
    timeout: int = typer.Option(10, "-t", "--timeout", help="Request timeout in seconds"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Save JSON to file"),
    nuclei_out: Optional[str] = typer.Option(None, "--nuclei-out", help="Write technology-tagged target groups as JSON"),
    workers: int = typer.Option(5, "-w", "--workers", help="Concurrent workers"),
    rate_limit: Optional[float] = typer.Option(None, "--rate-limit", help="Maximum requests per second per host"),
    cache: Optional[bool] = typer.Option(None, "--cache/--no-cache", help="Cache repeat scan results locally"),
    cache_path: Optional[str] = typer.Option(None, "--cache-path", help="SQLite cache path"),
    cache_ttl: int = typer.Option(86400, "--cache-ttl", help="Cache lifetime in seconds"),
    plugin_dir: Optional[str] = typer.Option(None, "--plugin-dir", help="Additional directory containing result plugins"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress banner"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Optional API key for enrichment services"),
    modules: Optional[list[str]] = typer.Option(None, "--module", "-m", help="Select recon modules: headers, dns, ssl, whois, subdomains, mail, tech, ports, extra, fast, full-recon, or all"),
    service: bool = typer.Option(False, "--service", help="Run service/technology fingerprint detection only"),
    headers: bool = typer.Option(False, "--headers", help="Enable header-based detection"),
    dns: bool = typer.Option(False, "--dns", help="Enable DNS enumeration"),
    ssl: bool = typer.Option(False, "--ssl", help="Enable SSL inspection"),
    whois: bool = typer.Option(False, "--whois", help="Enable whois lookup"),
    subdomains: bool = typer.Option(False, "--subdomains", help="Enable subdomain enumeration"),
    mail: bool = typer.Option(False, "--mail", help="Enable mail record lookup"),
    ports: bool = typer.Option(False, "--ports", help="Enable common port scanning"),
    extra: bool = typer.Option(False, "--extra", help="Enable extra reconnaissance intelligence"),
    fast: bool = typer.Option(False, "--fast", help="Fast scan preset (headers + tech)"),
    full_recon: bool = typer.Option(False, "--full-recon", help="Full recon preset"),
    all_modules: bool = typer.Option(False, "--all", help="Enable all recon modules"),
    smart: bool = typer.Option(False, "--smart", help="Enable smart detection heuristics and broader matching"),
    active: bool = typer.Option(False, "--active", help="Enable active reconnaissance checks such as directories and common ports"),
    passive: bool = typer.Option(False, "--passive", help="Enable passive recon sources such as crt.sh and public intel"),
    company: bool = typer.Option(False, "--company", help="Collect site and company metadata alongside recon results"),
    cve: Optional[bool] = typer.Option(None, "--cve/--no-cve", help="Correlate detected versions with the local CVE dataset"),
    cve_min_severity: Optional[str] = typer.Option(None, "--cve-min-severity", help="Minimum CVE severity: low, medium, high, or critical"),
    fail_on_cve: bool = typer.Option(False, "--fail-on-cve", help="Exit with code 2 when CVEs are found"),
    crawl: int = typer.Option(0, "--crawl", help="Fetch up to N additional same-origin pages to widen tech detection (0 disables)"),
    scope_path: Optional[str] = typer.Option(None, "--scope", help="YAML/JSON scope file"),
    max_requests: Optional[int] = typer.Option(None, "--max-requests", min=1, help="Maximum requests for one target"),
    respect_robots: bool = typer.Option(True, "--respect-robots/--ignore-robots", help="Respect robots.txt during crawl"),
    waf: bool = typer.Option(False, "--waf", help="Run passive WAF/CDN detection"),
    waf_probe: bool = typer.Option(False, "--waf-probe", help="Opt-in benign unusual-path WAF probe"),
    js_intel: bool = typer.Option(False, "--js-intel", help="Harvest and analyze JavaScript bundles"),
    api_surface: bool = typer.Option(False, "--api-surface", help="Check conventional API paths"),
    exposure: bool = typer.Option(False, "--exposure", help="Check bounded sensitive-file paths"),
    export_params: Optional[str] = typer.Option(None, "--export-params", help="Write mined JS parameter names to FILE"),
    save_history: bool = typer.Option(False, "--save-history", help="Append this scan's result to the local history DB for later 'inoue history' timelines"),
    history_path: Optional[str] = typer.Option(None, "--history-path", help="SQLite history DB path (default ~/.cache/inoue/history.db)"),
):
    """
    Inoue — tech stack fingerprinting CLI

    Detect frameworks, CMS, servers, CDN, WAF, analytics and more.

    Examples:\n
      inoue example.com\n
      inoue -v -e https://target.htb\n
      inoue --json -o out.json site1.com site2.com\n
      inoue --no-dns -t 5 10.10.11.55\n      inoue -m fast https://target.example\n      inoue -m full-recon https://target.example\n
    """
    if ctx.invoked_subcommand is not None:
        return

    config = load_config()
    global console, terminal_settings
    terminal_settings = load_terminal_settings(config)
    console = create_console(terminal_settings)
    if rate_limit is None:
        rate_limit = config.get("rate_limit")
    if cache is None:
        cache = bool(config.get("cache", False))
    if cache_path is None:
        cache_path = config.get("cache_path")
    if cache_ttl == 86400 and "cache_ttl" in config:
        cache_ttl = int(config["cache_ttl"])
    if cve is None:
        cve = bool(config.get("cve", False))
    if cve_min_severity is None:
        cve_min_severity = config.get("cve_min_severity")
    if plugin_dir is None:
        plugin_dir = config.get("plugin_dir")

    if targets and targets[0] == "history":
        command_args = targets[1:]
        if "--help" in command_args or "-h" in command_args:
            console.print("Usage: python inoue.py history TARGET [--history-path FILE] [--limit N] [--json]")
            raise typer.Exit()
        history_target = None
        history_db_path = None
        history_limit = 20
        history_json = False
        index = 0
        while index < len(command_args):
            argument = command_args[index]
            if argument == "--history-path" and index + 1 < len(command_args):
                history_db_path = command_args[index + 1]
                index += 2
                continue
            if argument == "--limit" and index + 1 < len(command_args):
                try:
                    history_limit = int(command_args[index + 1])
                except ValueError:
                    console.print(f"[red]invalid --limit value[/red] {command_args[index + 1]}")
                    raise typer.Exit(2)
                index += 2
                continue
            if argument == "--json":
                history_json = True
                index += 1
                continue
            if not argument.startswith("-") and history_target is None:
                history_target = argument
                index += 1
                continue
            console.print(f"[red]unknown history option[/red] {argument}")
            raise typer.Exit(2)
        if not history_target:
            console.print("[red]missing target[/red]. Usage: python inoue.py history TARGET")
            raise typer.Exit(2)
        run_history_command(history_target, history_path=history_db_path, limit=history_limit, json_out=history_json)
        raise typer.Exit()

    if targets and targets[0] == "update-cve":
        command_args = targets[1:]
        if "--help" in command_args or "-h" in command_args:
            console.print("Usage: python inoue.py update-cve [--source-url URL] [-o FILE]")
            raise typer.Exit()
        source_url = None
        output_path = None
        index = 0
        while index < len(command_args):
            argument = command_args[index]
            if argument == "--source-url" and index + 1 < len(command_args):
                source_url = command_args[index + 1]
                index += 2
                continue
            if argument in {"-o", "--output"} and index + 1 < len(command_args):
                output_path = command_args[index + 1]
                index += 2
                continue
            console.print(f"[red]unknown update-cve option[/red] {argument}")
            raise typer.Exit(2)
        update_cve(source_url=source_url, output=output_path)
        raise typer.Exit()

    try:
        targets = load_targets(targets, list_file)
    except OSError as exc:
        emit_cli_error(
            "Unable to read the supplied target list.",
            detail=str(exc),
            hint="Check the file path and permissions, then retry with inoue --help.",
            exit_code=2,
        )
    if not targets:
        emit_cli_error(
            "No target(s) were provided.",
            detail="Usage: inoue <target> [<target> ...] | inoue -l targets.txt",
            hint="Run 'inoue --help' for the full CLI reference.",
            exit_code=2,
        )

    if not no_banner and not json_out:
        print_banner()

    if tls_fingerprint:
        try:
            from core.tls_fingerprint import extract_tls_metadata
        except Exception:
            console.print("[yellow]TLS fingerprinting unavailable[/yellow]: optional TLS tooling is not installed; skipping best-effort metadata capture.")
            tls_fingerprint = False

    if any([service, headers, dns, ssl, whois, subdomains, mail, ports, extra, fast, full_recon, all_modules, smart, active, passive, company, cve, waf, waf_probe, js_intel, api_surface, exposure]) and modules is None:
        modules = []
    if modules is not None:
        modules = [m.lower() for m in modules]
    else:
        modules = []

    if service:
        modules.append("tech")
    if headers:
        modules.append("headers")
    if dns:
        modules.append("dns")
    if ssl:
        modules.append("ssl")
    if whois:
        modules.append("whois")
    if subdomains:
        modules.append("subdomains")
    if mail:
        modules.append("mail")
    if ports:
        modules.append("ports")
    if extra:
        modules.append("extra")
    if fast:
        modules.append("fast")
    if full_recon:
        modules.append("full-recon")
    if all_modules:
        modules.append("all")
    if smart:
        modules.append("smart")
    if active:
        modules.append("active")
    if passive:
        modules.append("passive")
    if company:
        modules.append("company")
    if cve:
        modules.append("cve")
    if waf or waf_probe:
        modules.append("waf")
    if js_intel:
        modules.append("js-intel")
    if api_surface:
        modules.append("api")
    if exposure:
        modules.append("exposure")
    if export_params and "js-intel" not in modules:
        modules.append("js-intel")

    if modules == []:
        modules = None

    results = []

    def maybe_capture_tls(result: ScanResult):
        if not tls_fingerprint or not result.final_url:
            return
        try:
            from urllib.parse import urlparse
            from core.tls_fingerprint import extract_tls_metadata
            parsed = urlparse(result.final_url)
            hostname = parsed.hostname or result.url
            metadata = extract_tls_metadata(hostname, port=443 if parsed.scheme == "https" else 80)
            if metadata.get("available"):
                result.ssl_info.update(metadata)
                result.tls_fingerprint = metadata.get("fingerprint", "")
        except Exception:
            pass

    def make_progress_callback(target: str, task_id: int):
        def callback(message: str):
            if json_out:
                return
            console.log(f"[dim]{target}[/dim] {message}")
            progress.update(task_id, description=f"  scanning {target}: {message}")
        return callback

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
        disable=json_out,
    ) as progress:
        tasks_map = {t: progress.add_task(f"  scanning {t}", total=None) for t in targets}
        if rate_limit or cache:
            results.extend(asyncio.run(scan_many(
                targets,
                timeout=timeout,
                dns=not no_dns,
                ssl_check=not no_ssl,
                api_key=api_key,
                modules=modules,
                workers=workers,
                rate_limit=rate_limit,
                cache_path=cache_path or "~/.cache/inoue/cache.db" if cache else None,
                cache_ttl=cache_ttl,
                plugin_dirs=[plugin_dir] if plugin_dir else None,
                cve_min_severity=cve_min_severity,
                crawl_pages=crawl,
                scope_path=scope_path,
                max_requests=max_requests,
                respect_robots=respect_robots,
                waf_probe=waf_probe,
            )))
            for target in targets:
                progress.remove_task(tasks_map[target])
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(
                        scan,
                        t,
                        timeout,
                        True,
                        not no_dns,
                        not no_ssl,
                        api_key=api_key,
                        modules=modules,
                        plugin_dirs=[plugin_dir] if plugin_dir else None,
                        cve_min_severity=cve_min_severity,
                        progress=make_progress_callback(t, tasks_map[t]),
                        crawl_pages=crawl,
                        scope_path=scope_path,
                        max_requests=max_requests,
                        respect_robots=respect_robots,
                        waf_probe=waf_probe,
                    ): t
                    for t in targets
                }

                for future in concurrent.futures.as_completed(futures):
                    target = futures[future]
                    progress.remove_task(tasks_map[target])
                    try:
                        result = future.result()
                        maybe_capture_tls(result)
                        results.append(result)
                    except Exception as e:
                        console.print(f"  [red]error[/red] {target}")
                        console.print(f"    [dim]{type(e).__name__}: {e}[/dim]")

    if save_history:
        from core.history import DEFAULT_HISTORY_PATH, record_snapshot
        from core.scanner import _serialize_scan_result
        db_path = history_path or DEFAULT_HISTORY_PATH
        saved_count = 0
        for result in results:
            if result.error:
                continue
            try:
                record_snapshot(db_path, result.url, _serialize_scan_result(result))
                saved_count += 1
            except Exception as exc:
                console.print(f"  [yellow]history save failed[/yellow] for {result.url}: {exc}")
        if saved_count and not json_out:
            console.print(f"  [green]saved[/green] {saved_count} snapshot(s) to {db_path}")
    if export_params:
        params = sorted({p for result in results for p in result.js_intel.get("parameters", [])})
        Path(export_params).write_text("\n".join(params) + ("\n" if params else ""), encoding="utf-8")
        if not json_out:
            console.print(f"  [green]saved[/green] {len(params)} parameters to {export_params}")

    if nuclei_out:
        try:
            write_nuclei_export(results, nuclei_out)
            console.print(f"  [green]saved[/green] {nuclei_out}")
        except Exception as exc:
            emit_cli_error(
                "Failed to write the nuclei export.",
                detail=str(exc),
                hint=f"Check permissions and the output path: {nuclei_out}",
                exit_code=1,
            )

    if json_out or output:
        json_str = json.dumps([result_to_dict(result) for result in results], indent=2)
        if output:
            suffix = Path(output).suffix.lower()
            try:
                if suffix == ".html":
                    Path(output).write_text(render_html_report(results), encoding="utf-8")
                elif suffix == ".md":
                    Path(output).write_text(render_markdown_report(results), encoding="utf-8")
                else:
                    Path(output).write_text(json_str, encoding="utf-8")
                console.print(f"  [green]saved[/green] {output}")
            except OSError as exc:
                emit_cli_error(
                    "Unable to write the output file.",
                    detail=str(exc),
                    hint=f"Verify that the path is writable: {output}",
                    exit_code=1,
                )
        if json_out:
            print(json_str)
        exit_code = result_exit_code(results, bool(cve), fail_on_cve)
        if exit_code:
            raise typer.Exit(exit_code)
        return

    for result in results:
        maybe_capture_tls(result)
        if len(results) > 1:
            console.print(f"[dim]  ── {result.url} {'─' * max(0, 50 - len(result.url))}[/dim]")
        if result.error:
            console.print(f"  [red]error[/red] {result.error}\n")
            continue
        render_result(result, verbose=verbose, evidence=evidence, modules=modules)

    exit_code = result_exit_code(results, bool(cve), fail_on_cve)
    if exit_code:
        raise typer.Exit(exit_code)


if __name__ == "__main__":
    app()
