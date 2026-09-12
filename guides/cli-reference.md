# Inoue CLI reference

This is the reference for the global `inoue` command and the equivalent local Python entry point.

## Command forms

Use the installed global command:

```bash
inoue --help
inoue alhamrizvi.in
inoue -v -e https://alhamrizvi.in
```

Use the repository entry point during local development:

```bash
python inoue.py --help
python inoue.py alhamrizvi.in
```

The installed command is the intended production path. The Python file is still supported for local development and debugging.

## Common commands

### Basic scan

```bash
inoue alhamrizvi.in
```

### Verbose scan

```bash
inoue -v alhamrizvi.in
```

### Evidence output

```bash
inoue -e https://alhamrizvi.in
```

### JSON output

```bash
inoue --json alhamrizvi.in
inoue --json -o results.json alhamrizvi.in
```

### HTML report output

```bash
inoue -o report.html alhamrizvi.in
```

### Markdown report output

```bash
inoue -o report.md alhamrizvi.in
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
inoue --fast alhamrizvi.in
inoue -m fast alhamrizvi.in
```

### Full recon mode

```bash
inoue --full-recon alhamrizvi.in
inoue -m full-recon alhamrizvi.in
```

### Service only mode

```bash
inoue --service alhamrizvi.in
```

### Header only mode

```bash
inoue --headers alhamrizvi.in
```

### DNS only mode

```bash
inoue --dns alhamrizvi.in
```

### SSL only mode

```bash
inoue --ssl alhamrizvi.in
```

### Whois only mode

```bash
inoue --whois alhamrizvi.in
```

### Subdomain mode

```bash
inoue --subdomains alhamrizvi.in
```

### Mail record mode

```bash
inoue --mail alhamrizvi.in
```

### Port scan mode

```bash
inoue --ports alhamrizvi.in
```

### Extra recon mode

```bash
inoue --extra alhamrizvi.in
```

## Global options

### Timeout

```bash
inoue -t 15 alhamrizvi.in
```

### Worker count

```bash
inoue -w 10 alhamrizvi.in
```

### Network rate limiting

```bash
inoue --rate-limit 2 alhamrizvi.in
```

### Disable banner

```bash
inoue --no-banner alhamrizvi.in
```

### Set an API key for enrichment services

```bash
inoue --api-key yourkey alhamrizvi.in
```

## Cache options

Enable caching:

```bash
inoue --cache alhamrizvi.in
```

Set a custom cache path:

```bash
inoue --cache --cache-path /tmp/inoue-cache.db alhamrizvi.in
```

Set a custom cache TTL:

```bash
inoue --cache --cache-ttl 3600 alhamrizvi.in
```

## CVE matching

Enable local CVE correlation:

```bash
inoue --cve alhamrizvi.in
```

Set a minimum severity floor:

```bash
inoue --cve --cve-min-severity high alhamrizvi.in
```

Fail exit if a CVE match is found:

```bash
inoue --cve --fail-on-cve alhamrizvi.in
```

Refresh the local CVE store:

```bash
inoue update-cve
```

## Export commands

### Nuclei output

```bash
inoue --nuclei-out targets.json alhamrizvi.in
```

### JSON export file

```bash
inoue --json -o results.json alhamrizvi.in
```

### HTML export file

```bash
inoue -o report.html alhamrizvi.in
```

### Markdown export file

```bash
inoue -o report.md alhamrizvi.in
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
