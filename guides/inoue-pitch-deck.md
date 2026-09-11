# Inoue 13 Slide Pitch Deck Outline

## Slide 1: Title, Inoue is the next generation web stack intelligence layer
- The market is full of noisy, fragmented stack detectors.
- Most tools are either too shallow, too generic, or too focused on single vendors.
- Inoue turns reconnaissance into a structured, explainable, attack-surface intelligence system.
- Core promise: faster, deeper, safer, more trustworthy detection for product, security, and research workflows.

## Slide 2: The problem, the stack landscape is fragmented and noisy
- Wappalyzer-style tools are helpful but often shallow and inconsistent.
- Browser extensions are good for quick checks, but not full operational workflows.
- CLI tools usually lack modern output quality, version confidence, and CVE context.
- Security teams need evidence, not guesses.

## Slide 3: The opportunity, a unified recon and intelligence platform
- One engine for CLI, API, batch jobs, and browser workflows.
- Single source of truth for detection logic and evidence collection.
- Works across public web recon, internal review, product mapping, and security intelligence.
- Designed for both humans and automation.

## Slide 4: Why Inoue is different
- Signal-aware scoring instead of one-hit matches
- Confidence + evidence + version tracking
- Read-only recon posture by default
- Stronger handling of false positives, redirect hops, and noisy frameworks
- Better compatibility with CVE awareness and structured output

## Slide 5: Comparison, Inoue versus Wappalyzer and browser only tools
- Wappalyzer: fast but often shallow, less transparent, weaker explainability
- Built-in browser detectors: convenience only, usually limited scope and no local engine depth
- Nmap/other recon tools: useful for ports/services but not stack intelligence
- Inoue: combined detection depth, better evidence, structured output, API + CLI + extension

## Slide 6: Comparison, Inoue versus generic scanners and manual recon
- Manual recon is slow and inconsistent
- Generic scanners produce service-level signals, not app-stack insights
- Inoue compresses the manual triage process into a readable, structured report
- Better for bug bounty, product analysis, and portfolio intelligence workflows

## Slide 7: Product vision, from fingerprinting to intelligence
- Today: detect technologies and versions
- Next: expose confidence, risk posture, drift, and ecosystem context
- Future: watch mode, diffs, alerts, historical snapshots, and integration feeds
- Long-term: stack intelligence as a decision layer for security and product teams

## Slide 8: Architecture, the core engine keeps the truth centralized
- Scanner core handles HTTP metadata, HTML, script paths, headers, cookies, URL patterns
- Catalog drives detection, version capture, and suppression rules
- API exposes safe, structured scans
- Browser extension consumes the same backend without duplicating logic

## Slide 9: Technical superiority, evidence, confidence, and filtering
- Technology match quality depends on signal strength
- False-positive protection via excludes and contradiction notes
- Version normalization rejects timestamps and noisy IDs
- Detection is reviewable by analysts rather than opaque black-box magic

## Slide 10: Security and integrity, built for trust, not abuse
- Read-only recon posture
- API blocks private targets by default
- Batch size and rate limiting
- Revalidation on redirect hops
- No exploit automation or offensive toolkit behavior

## Slide 11: Business value, who benefits and why
- Security teams: faster triage and live stack awareness
- Product teams: better technology landscape visibility
- Bug bounty researchers: targeted, evidence-backed recon
- MSSPs and consultants: repeatable client-facing reports and exports

## Slide 12: Roadmap, from better detector to intelligence platform
- Real-time diff monitoring and watch scans
- Stronger TLS and certificate intelligence
- More catalog import rigor and validation workflows
- Better reporting, exports, and automation integrations
- Better multi-tenant, API-first deployment capabilities

## Slide 13: Closing, Inoue is the better weaponized version of stack detection
- It is not just a plugin or a browser helper; it is a full stack intelligence system
- It beats shallow tools by making detection explainable, reproducible, and operational
- It is built to scale from one-off recon to recurring monitoring and reporting
- The future is not just “what is this app?” It is “what does this stack tell us, how risky is it, and how do we monitor it over time?”
