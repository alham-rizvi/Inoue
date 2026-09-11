# Agent Overview

This repository is a lightweight recon and technology fingerprinting CLI. It is designed to identify the stack behind a target website or service without requiring a large web application server or backend.

## What the project does

The tool fetches a target over HTTP(S), inspects response metadata, and matches the output against a large catalog of known signatures. It can flag frameworks, CMS systems, languages, CDNs, WAFs, admin panels, analytics stacks, payment providers, API docs, and many self-hosted platforms.

It is aimed at:

- recon and enumeration workflows
- bug bounty surface analysis
- CTF and HTB-style environment review
- internal security review and footprint mapping
- public-facing technology discovery

## Repository layout

- `inoue.py` for the command line entry point and user facing output
- `core/scanner.py` for scan orchestration, fingerprint matching, recon modules, and helper functions
- `fingerprints/signatures.py` for the signature catalog used in detection
- `fingerprints/extended_catalog.py` for the supplementary signature set and extended technology mapping
- `tests/test_scanner.py` for regression tests covering detection and CLI behavior
- `SECURITY.md` for the supported version and valid security reporting expectations

## High-level execution flow

1. The CLI receives one or more targets and optional flags.
2. The command layer calls the scanner with the selected modules and timeout settings.
3. The scanner issues an HTTP request and captures headers, cookies, and the response body.
4. Fingerprint matching runs against the signature catalog.
5. Recon modules can optionally inspect DNS, SSL, WHOIS, subdomains, ports, and public intel.
6. The final result is rendered as terminal output or JSON output.

## Critical implementation areas

### CLI and UX

The main CLI in `inoue.py` is responsible for:

- argument parsing and flag handling
- execution of scans for multiple targets
- structured JSON output and file writing
- progress reporting and result rendering
- repository update support

This is the user-facing layer and should be treated as the interface contract for the tool.

### Detection engine

The detection work is concentrated in `core/scanner.py`:

- `run_fingerprints()` matches technologies against headers, HTML, scripts, cookies, meta tags, and URL paths
- `build_recon_plan()` decides which scan modules are active
- helper functions resolve DNS, SSL, WHOIS, subdomains, and mail records
- result data structures keep findings in a consistent format for rendering and export

This is the most important place to review when adjusting detection quality, speed, or module behavior.

### Signature catalog

`fingerprints/signatures.py` contains the technology definitions. Each signature is a mapping of technology name to rules such as:

- HTTP headers
- cookies
- HTML patterns
- script URL patterns
- meta tags
- path-based routes

The scanner uses a compiled lookup map to filter candidate technologies before full matching. That makes it fast and keeps the detection logic manageable.

## Important security model

This project is not a privileged network service. Its security considerations are mostly local and operational:

- safe handling of CLI arguments and output paths
- safe outbound HTTP behavior
- limiting unsafe automation in local CI or shell execution paths
- preventing misuse of self-update routines or repository operations

It is a recon tool, so normal discovery against public endpoints is expected behavior and is not treated as a vulnerability by itself.

## Expected review areas for future changes

When making changes, review these areas first:

1. `run_fingerprints()` behavior and candidate filtering logic
2. route/path heuristics for API or admin surfaces
3. HTTP handling, timeout control, and redirect behavior
4. DNS/SSL/WHOIS fallback logic for reliability and safety
5. JSON output and CLI contract compatibility
6. updates and release automation in the CLI

## Practical guidance

If you are extending the tool, keep changes small and behavior-driven. Prefer adding a new signature or path heuristic over altering broad matching logic without tests. The expected regression safety net is the existing suite in `tests/test_scanner.py`.

This project is intentionally compact, so an agent or reviewer can understand the whole system by reading the CLI entry point, the scanner engine, and the signature catalog together.
