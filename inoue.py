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
from core.scanner import build_service_summary, scan, scan_many, ScanResult

app = typer.Typer(help="Inoue — tech stack fingerprinting CLI", add_completion=False)
console = Console()


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
/_/_/ /_/\____/\__,_/\___/ """ + f"[/bold white][dim]v{APP_VERSION}  tech stack fingerprinting[/dim]\n")


def render_result(result: ScanResult, verbose: bool = False, evidence: bool = False, modules: Optional[list[str]] = None):
    status_color = "green" if result.status_code < 300 else "yellow" if result.status_code < 400 else "red"

    console.print(f"  [dim]url[/dim]     {result.final_url}")
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

        table = Table(box=None, show_header=True, header_style="dim", padding=(0, 2, 0, 0), show_edge=False)
        table.add_column("category", width=20)
        table.add_column("technology", width=22)
        table.add_column("version", width=14)
        table.add_column("confidence", width=12)
        if evidence:
            table.add_column("evidence", width=55)

        for category in sorted(by_category.keys()):
            techs = by_category[category]
            color = CATEGORY_COLORS.get(category, "white")
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

    if result.mail_records and verbose:
        console.print("  [dim]── mail records ─────────────────────[/dim]")
        for item in result.mail_records:
            console.print(f"  [cyan]MX[/cyan] {item}")
        console.print()

    if result.subdomains:
        console.print("  [dim]── subdomains ───────────────────────[/dim]")
        for item in result.subdomains[:12]:
            console.print(f"  [cyan]sub[/cyan] {item}")
        if len(result.subdomains) > 12:
            console.print(f"  [dim]+{len(result.subdomains) - 12} more[/dim]")
        console.print()

    if result.directories:
        console.print("  [dim]── directories ───────────────────────[/dim]")
        for item in result.directories[:10]:
            console.print(f"  [cyan]{item['source']}[/cyan] {item['path']} -> {item['status_code']}")
        console.print()

    if result.extra_intel and verbose:
        console.print("  [dim]── public intel ─────────────────────[/dim]")
        for key, value in result.extra_intel.items():
            if isinstance(value, list):
                console.print(f"  [cyan]{key}[/cyan] {', '.join(str(v) for v in value[:8])}")
            else:
                console.print(f"  [cyan]{key}[/cyan] {value}")
        console.print()

    if result.ssl_info and not result.ssl_info.get("error") and verbose:
        ssl = result.ssl_info
        subject = ssl.get("subject", {})
        issuer = ssl.get("issuer", {})
        console.print("  [dim]── ssl ──────────────────────────────[/dim]")
        console.print(f"  [dim]protocol[/dim]  {ssl.get('protocol', '?')}  [dim]cipher[/dim] {ssl.get('cipher', '?')}")
        console.print(f"  [dim]issued to[/dim] {subject.get('commonName', '?')}")
        console.print(f"  [dim]issued by[/dim] {issuer.get('organizationName', '?')}")
        console.print(f"  [dim]valid[/dim]     {ssl.get('notBefore', '?')}  →  {ssl.get('notAfter', '?')}")
        if ssl.get("san"):
            sans = ssl["san"][:6]
            console.print(f"  [dim]san[/dim]       {', '.join(sans)}" + (" ..." if len(ssl["san"]) > 6 else ""))
        console.print()

    if result.dns_records and verbose:
        console.print("  [dim]── dns ───────────────────────────────[/dim]")
        for rtype, values in result.dns_records.items():
            for v in values[:5]:
                console.print(f"  [cyan]{rtype:<8}[/cyan] {v}")
        console.print()

    if verbose:
        sec_headers = [
            "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
            "X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy",
            "Permissions-Policy", "Cross-Origin-Opener-Policy",
        ]
        console.print("  [dim]── security headers ────────────────────[/dim]")
        for h in sec_headers:
            v = result.headers.get(h, result.headers.get(h.lower(), ""))
            if v:
                console.print(f"  [green]+[/green] [dim]{h}[/dim]")
            else:
                console.print(f"  [red]-[/red] [dim]{h}[/dim]")
        console.print()

    if verbose:
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
    console.print("  - python inoue.py -m fast https://target.example")
    console.print("  - python inoue.py -m full-recon https://target.example")


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


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    targets: Optional[list[str]] = typer.Argument(None, help="Target URLs or IPs (e.g. example.com, 10.10.11.2)"),
    list_file: Optional[str] = typer.Option(None, "-l", "--list", help="Read one target per line from FILE"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show SSL, DNS, security headers, all headers"),
    evidence: bool = typer.Option(False, "-e", "--evidence", help="Show detection evidence"),
    no_dns: bool = typer.Option(False, "--no-dns", help="Skip DNS enumeration"),
    no_ssl: bool = typer.Option(False, "--no-ssl", help="Skip SSL inspection"),
    timeout: int = typer.Option(10, "-t", "--timeout", help="Request timeout in seconds"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON"),
    output: Optional[str] = typer.Option(None, "-o", "--output", help="Save JSON to file"),
    nuclei_out: Optional[str] = typer.Option(None, "--nuclei-out", help="Write technology-tagged target groups as JSON"),
    workers: int = typer.Option(5, "-w", "--workers", help="Concurrent workers"),
    rate_limit: Optional[float] = typer.Option(None, "--rate-limit", help="Maximum requests per second per host"),
    cache: bool = typer.Option(False, "--cache", help="Cache repeat scan results locally"),
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
    cve: bool = typer.Option(False, "--cve", help="Correlate detected versions with the local CVE dataset"),
    cve_min_severity: Optional[str] = typer.Option(None, "--cve-min-severity", help="Minimum CVE severity: low, medium, high, or critical"),
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

    targets = load_targets(targets, list_file)
    if not targets:
        typer.echo("Missing target(s).", err=True)
        raise typer.Exit(2)

    if not no_banner and not json_out:
        print_banner()

    if any([service, headers, dns, ssl, whois, subdomains, mail, ports, extra, fast, full_recon, all_modules, smart, active, passive, company, cve]) and modules is None:
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

    if modules == []:
        modules = None

    results = []

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
                    ): t
                    for t in targets
                }

                for future in concurrent.futures.as_completed(futures):
                    target = futures[future]
                    progress.remove_task(tasks_map[target])
                    try:
                        results.append(future.result())
                    except Exception as e:
                        console.print(f"  [red]error[/red] {target}: {e}")

    if nuclei_out:
        write_nuclei_export(results, nuclei_out)
        console.print(f"  [green]saved[/green] {nuclei_out}")

    if json_out or output:
        out = []
        for r in results:
            out.append({
                "url": r.url,
                "final_url": r.final_url,
                "ip": r.ip,
                "status_code": r.status_code,
                "response_time_ms": r.response_time_ms,
                "server": r.server,
                "technologies": [
                    {
                        "name": t.name,
                        "category": t.category,
                        "version": t.version,
                        "confidence": t.confidence,
                        "confidence_score": t.confidence_score,
                        "evidence": t.evidence,
                        "cves": t.cves,
                    }
                    for t in r.technologies
                ],
                "dns": r.dns_records,
                "ssl": r.ssl_info,
                "recon": r.enriched.get("recon", []) if r.enriched else [],
                "service_hints": r.enriched.get("service_hints", []) if r.enriched else [],
                "plugins": r.enriched.get("plugins", {}) if r.enriched else {},
                "notes": r.notes,
                "error": r.error,
            })
        json_str = json.dumps(out, indent=2)
        if output:
            with open(output, "w") as f:
                f.write(json_str)
            console.print(f"  [green]saved[/green] {output}")
        if json_out:
            print(json_str)
        return

    for result in results:
        if len(results) > 1:
            console.print(f"[dim]  ── {result.url} {'─' * max(0, 50 - len(result.url))}[/dim]")
        if result.error:
            console.print(f"  [red]error[/red] {result.error}\n")
            continue
        render_result(result, verbose=verbose, evidence=evidence, modules=modules)


if __name__ == "__main__":
    app()
