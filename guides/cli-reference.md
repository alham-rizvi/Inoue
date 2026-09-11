# Inoue CLI reference

This is the reference for the global `inoue` command and the equivalent local Python entry point.

## Command forms

Use the installed global command:

```bash
inoue --help
inoue example.com
inoue -v -e https://example.com
```

Use the repository entry point during local development:

```bash
python inoue.py --help
python inoue.py example.com
```

The installed command is the intended production path. The Python file is still supported for local development and debugging.

## Common commands

### Basic scan

```bash
inoue example.com
```

### Verbose scan

```bash
inoue -v example.com
```

### Evidence output

```bash
inoue -e https://example.com
```

### JSON output

```bash
inoue --json example.com
inoue --json -o results.json example.com
```

### HTML report output

```bash
inoue -o report.html example.com
```

### Markdown report output

```bash
inoue -o report.md example.com
```

### Multi target scan

```bash
inoue site1.com site2.com site3.com
```

### Read targets from a file

```bash
inoue --list targets.txt
```

### Input from stdin

```bash
cat targets.txt | inoue --json
```

## Module based scans

### Fast mode

```bash
inoue --fast example.com
inoue -m fast example.com
```

### Full recon mode

```bash
inoue --full-recon example.com
inoue -m full-recon example.com
```

### Service only mode

```bash
inoue --service example.com
```

### Header only mode

```bash
inoue --headers example.com
```

### DNS only mode

```bash
inoue --dns example.com
```

### SSL only mode

```bash
inoue --ssl example.com
```

### Whois only mode

```bash
inoue --whois example.com
```

### Subdomain mode

```bash
inoue --subdomains example.com
```

### Mail record mode

```bash
inoue --mail example.com
```

### Port scan mode

```bash
inoue --ports example.com
```

### Extra recon mode

```bash
inoue --extra example.com
```

## Global options

### Timeout

```bash
inoue -t 15 example.com
```

### Worker count

```bash
inoue -w 10 example.com
```

### Network rate limiting

```bash
inoue --rate-limit 2 example.com
```

### Disable banner

```bash
inoue --no-banner example.com
```

### Set an API key for enrichment services

```bash
inoue --api-key yourkey example.com
```

## Cache options

Enable caching:

```bash
inoue --cache example.com
```

Set a custom cache path:

```bash
inoue --cache --cache-path /tmp/inoue-cache.db example.com
```

Set a custom cache TTL:

```bash
inoue --cache --cache-ttl 3600 example.com
```

## CVE matching

Enable local CVE correlation:

```bash
inoue --cve example.com
```

Set a minimum severity floor:

```bash
inoue --cve --cve-min-severity high example.com
```

Fail exit if a CVE match is found:

```bash
inoue --cve --fail-on-cve example.com
```

Refresh the local CVE store:

```bash
inoue update-cve
```

## Export commands

### Nuclei output

```bash
inoue --nuclei-out targets.json example.com
```

### JSON export file

```bash
inoue --json -o results.json example.com
```

### HTML export file

```bash
inoue -o report.html example.com
```

### Markdown export file

```bash
inoue -o report.md example.com
```

## Update commands

Refresh repository data and application updates:

```bash
inoue update
```

## Exit behavior

The CLI returns meaningful exit codes:

- 0 for successful scans without CVE fail conditions
- 1 for scan or runtime errors
- 2 for explicit CVE fail conditions or argument errors

This makes the CLI easier to use in automation and scripting.

## Notes on global command usage

When the package is installed correctly, the command is globally available in the shell. That is the default supported UX for end users and automation scripts.

This is the preferred pattern for docs and examples because it reflects the real production install path.

## Summary

The CLI is designed around a simple pattern:

```bash
inoue [flags] [target ...]
```

The same underlying scanner engine powers CLI runs, API scans, and browser extension scans, which keeps the project behavior consistent across interfaces.
