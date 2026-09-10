# Changelog

## 1.1.2 - 2026-09-10

### Added

- bounded watch-scan execution and result diffs for technologies, CVEs, ports,
  and certificate expiry;
- generic, Slack, and Discord webhook payload builders plus HTTPS delivery;
- TLS metadata and known CDN/WAF fingerprint helpers;
- optional FastAPI service endpoints for health, signatures, single scans, and
  batch scans;
- Wappalyzer normalization and duplicate catalog compatibility checks;
- optional EPSS score retention in offline CVE correlation;
- Docker and Compose deployment definitions;
- GitHub Actions PyPI publishing with wheel and sdist validation.

### Fixed

- Python 3.12 plugin imports now defer type annotation evaluation;
- published wheels now include the bundled offline CVE dataset.

## 1.1.0

See the GitHub release notes for the previous release.