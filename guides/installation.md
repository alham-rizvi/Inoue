# Inoue installation and setup

This guide covers the supported ways to install Inoue, configure the global command, run the CLI, and start the optional API and extension workflows.

## Install from PyPI

Install the package from PyPI:

```bash
python -m pip install inoue
inoue --help
```

For API support:

```bash
python -m pip install "inoue[api]"
```

For MCP support:

```bash
python -m pip install "inoue[mcp]"
inoue-mcp --help
```

## Install from source

Clone the repository and install it into the active environment:

```bash
git clone https://github.com/alham-rizvi/Inoue.git
cd Inoue
python -m pip install -r requirements.txt
python -m pip install -e .
```

After that, the global CLI command becomes available on PATH:

```bash
inoue --help
```

This is the preferred development flow when working on local fixes or custom catalog changes.

## Global command behavior

The package exposes the console script named `inoue` through the project entry point in `pyproject.toml`.

This means you can run the tool in normal shell usage without referencing the Python file directly:

```bash
inoue alhamrizvi.in
inoue -v -e https://alhamrizvi.in
inoue --json -o results.json https://alhamrizvi.in
```

The Python entry point is also still valid for local development:

```bash
python inoue.py alhamrizvi.in
```

The installed command is the recommended path for docs, automation, and production usage.

## Environment and configuration

Inoue reads configuration from these locations, with CLI flags taking precedence:

1. project local config file called `.inoue.toml`
2. user config file at `~/.config/inoue/config.toml`
3. command line flags passed to the CLI

Example config:

```toml
[terminal]
text_style = "bright_white"
layout = "wide"

[terminal.colors]
"Web Server" = "bright_cyan"
"CMS" = "yellow"

[general]
cache = true
cache_ttl = 86400
cve = true
cve_min_severity = "medium"
```

Example values are illustrative. The scanner uses operational config such as cache, rate limiting, API key usage, and CVE behavior.

## Optional API setup

If the optional API dependencies are installed, start the API with uvicorn:

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Then test it with:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/signatures
```

Single scan request:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://alhamrizvi.in","modules":["fast"]}'
```

Batch scan request:

```bash
curl -X POST http://127.0.0.1:8000/scan/batch \
  -H 'Content-Type: application/json' \
  -d '{"targets":["https://alhamrizvi.in","https://example.org"],"workers":2}'
```

## Browser extension setup

The extension is kept in the repository under `extension/`.

Development flow:

```bash
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
python scripts/build_extension.py
```

Load the unpacked directory or the produced zip archive in Chrome or Firefox:

- Chrome: chrome://extensions, then load unpacked
- Firefox: about:debugging, then load temporary add on

## Docker option

The repository includes a Dockerfile and docker-compose setup for containerized usage when relevant dependencies are present.

Example:

```bash
docker build -t inoue .
docker run --rm -it inoue --help
```

For compose:

```bash
docker compose up --build
```

## Verification commands

Use these commands to confirm the install is correct:

```bash
inoue --help
inoue about
inoue alhamrizvi.in
```

A working install should show the banner and render a result for a reachable target. If a scan fails, check the error details and verify the network path, TLS settings, and target accessibility.

## Troubleshooting

### command not found

If `inoue` is not recognized, reinstall the package and confirm the environment PATH includes the Python user scripts directory:

```bash
python -m pip install -e .
which inoue
inoue --help
```

### API not reachable

Check whether the API is running and the port is correct:

```bash
curl http://127.0.0.1:8000/health
```

### Extension cannot connect to API

Check these items:

- API is running locally on 127.0.0.1 port 8000
- the extension storage has the correct API URL
- the host permission includes localhost or the chosen remote origin
- the API key is set if the backend requires authentication

## Summary

Inoue is designed to be used as a global command first and as a Python module second. The install flow is simple, the CLI is designed for daily use, and the API and extension are thin adapters over the same scanner core. This keeps the behavior consistent across the project.
