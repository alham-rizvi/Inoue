# Inoue Wiki

This page is the repository-maintained operating guide for Inoue. It covers
installation, verification, terminal customization, MCP, containers, and
release publishing.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest tests/ -q
python inoue.py --help
```

Install the package and optional integrations with:

```bash
python -m pip install .
python -m pip install ".[api]"
python -m pip install ".[mcp]"
```

## Terminal themes

Create `.inoue.toml` in the project directory or edit
`~/.config/inoue/config.toml`:

```toml
[terminal]
text_style = "bright_white"
layout = "wide" # compact, standard, or wide

[terminal.colors]
"Web Server" = "bright_cyan"
"Application Server" = "green"
"CMS" = "yellow"
"Other" = "grey70"
```

The settings affect Rich terminal presentation only. JSON and HTML output keep
their stable machine-readable shape.

## MCP server

Inoue provides an optional stdio MCP adapter:

```bash
python -m pip install ".[mcp]"
inoue-mcp
```

Tools:

- `search_catalog`: local, network-free signature search;
- `get_catalog_summary`: category and total signature counts;
- `scan_read_only`: the existing read-only scanner.

No exploit, credential, write, or attack-automation tool is exposed.

## Docker

Validate and start the local container:

```bash
docker compose config
docker compose build
docker compose run --rm inoue
```

The Compose file persists only the opt-in cache. The bundled CVE dataset stays
visible inside the image; refresh a separate dataset explicitly with
`update-cve --output PATH` when needed.

## Verification

Run the same checks used by the repository workflows:

```bash
python -m pytest tests/ -q
python -m pytest tests/ -q --collect-only
python -m pytest tests/ -q -W error
python scripts/check_signatures.py
python -m compileall -q core api fingerprints inoue.py mcp_server.py
python -m build
python -m twine check dist/*
```

## PyPI publishing

Publishing uses GitHub Actions trusted publishing. Before creating a GitHub
release, configure a PyPI trusted publisher for:

- owner: `alham-rizvi`;
- repository: `Inoue`;
- workflow: `publish.yml`;
- environment: `pypi`;
- package: `inoue`.

The GitHub workflow grants only `contents: read` and `id-token: write`, builds
and validates the wheel and source distribution, then publishes on a published
GitHub release. A missing PyPI publisher produces `invalid-publisher`; that is
an account configuration issue, not a package build failure.

Release checklist:

1. Bump `pyproject.toml` and update `CHANGELOG.md`.
2. Run the verification commands above.
3. Push the commit to `main`.
4. Create an annotated tag and GitHub release, for example `v1.1.3`.
5. Confirm the `publish-package` workflow and PyPI project page.