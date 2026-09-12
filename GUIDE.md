# Inoue extension and update guide

This repository supports three main maintenance workflows:

1. Expand the fingerprint catalog with more services, cloud portals, ICS/SCADA surfaces, and admin panels.
2. Improve version detection by combining header, HTML, script, and path-based heuristics.
3. Update the local clone automatically from the repository via the built-in `update` command.

## 1. Expand the catalog

The main signature catalog is stored in [fingerprints/signatures.py](fingerprints/signatures.py) and is merged with the extended catalog in [fingerprints/extended_catalog.py](fingerprints/extended_catalog.py).

To add a new service:

- Open [fingerprints/signatures.py](fingerprints/signatures.py)
- Add a new entry in the `SIGNATURES` dictionary using the existing schema
- Optionally add a companion entry in [fingerprints/extended_catalog.py](fingerprints/extended_catalog.py) if you want it to be part of the broader generated catalog

Example:

```python
"Example Portal": {
    "category": "Cloud",
    "html": [r"Example Portal", r"example-portal"],
    "paths": [r"/login", r"/admin"],
}
```

### Signature schema reference

Each signature entry in the `SIGNATURES` dictionary follows this schema:

```python
"Service Name": {
    "category": "Category",           # Required: Type of service (e.g., "Web Server", "CMS", "Cloud", etc.)
    "headers": {                      # Optional: HTTP headers to match
        "Header-Name": r"pattern",
        "Server": r"Service(?:/([0-9.]+))?",  # Use regex groups to capture version
    },
    "cookies": [r"pattern1", r"pattern2"],    # Optional: Cookie values to match
    "html": [r"pattern1", r"pattern2"],       # Optional: HTML body patterns
    "meta": {"property": r"pattern"},         # Optional: Meta tag patterns
    "script": [r"pattern1", r"pattern2"],     # Optional: Script source patterns
    "paths": [r"/api", r"/admin"],            # Optional: URL path patterns
}
```

## 2. Improve version detection

Version detection now uses a layered approach:

- **Header regex capture groups**: Extract versions directly from header values using named groups
- **Body pattern groups**: Capture versions from HTML content patterns
- **Contextual hints**: Extract nearby version-like strings in response content
- **Path and script hints**: Extract versions from URL paths such as `/v2.3.1/` or script source URLs

When adding a signature, prefer regex capture groups that extract versions directly:

```python
"Example Service": {
    "category": "Cloud",
    "headers": {"Server": r"ExampleService(?:/([0-9.]+))?"},
    "html": [r"ExampleService v([0-9.]+)"],
}
```

The scanner will normalize versions such as `1.2.3`, `v1.2.3`, `release-2.4`, and similar forms.

### Version normalization examples

The scanner handles these common version formats:
- `1.2.3` → `1.2.3`
- `v1.2.3` → `1.2.3`
- `release-2.4` → `2.4`
- `Version: 3.0.1` → `3.0.1`

## 3. Update the tool automatically

The CLI includes an update command that fetches the latest fingerprints, scanner improvements, and catalog changes:

```bash
python inoue.py update
```

### How the update mechanism works

The update process performs the following steps:

1. **Fetch from remote**: Runs `git fetch --all --prune` to pull all remote changes
2. **Pull changes**: Runs `git pull --ff-only` to merge only fast-forward updates (avoiding merge conflicts)
3. **Report changes**: Displays the last 5 commits and lists modified files
4. **Apply changes immediately**: Updated signatures and scanner logic are loaded on next execution

### Files that are updated

When you run `python inoue.py update`, the following key files may be refreshed:

| File | Purpose | Impact |
|------|---------|--------|
| `fingerprints/signatures.py` | Core fingerprint catalog | New/updated service signatures available immediately |
| `fingerprints/extended_catalog.py` | Extended/community catalog | Additional detection rules for niche services |
| `core/scanner.py` | Scanner engine and detection logic | Improved detection heuristics and version extraction |
| `core/__init__.py` | Core module initialization | Module interface updates |
| `inoue.py` | CLI interface and commands | New features, improved output, bug fixes |
| `GUIDE.md`, `CONTRIBUTING.md` | Documentation | Updated contribution guidelines |

### Contributing changes that will be fetched via update

When contributing new signatures or improvements, keep these guidelines in mind:

- **Focused PRs**: Each PR should focus on one area (e.g., adding signatures for a category or improving version detection)
- **Signature additions**: Add entries to `fingerprints/signatures.py` with proper regex patterns and categories
- **Testing**: Ensure changes pass the test suite before submitting
- **Documentation**: Update relevant comments in code if adding new detection methods
- **Catalog consistency**: Keep the main `signatures.py` focused on widely-deployed services; use `extended_catalog.py` for niche/regional services

### Example: Contributing a new signature via PR

1. Fork the repository
2. Create a feature branch: `git checkout -b add-example-service`
3. Edit `fingerprints/signatures.py`:
   ```python
   "Example Portal": {
       "category": "Cloud",
       "headers": {"X-Example": r"ExamplePortal/([0-9.]+)"},
       "html": [r"Powered by Example Portal"],
       "paths": [r"/admin", r"/login"],
   }
   ```
4. Test locally: `python -m unittest discover -s tests -p 'test*.py' -q`
5. Commit with clear message: `git commit -m "Add Example Portal fingerprint for cloud category"`
6. Push and create a pull request with evidence of detection (e.g., screenshot, curl output)

### How users receive your updates

Users with your changes in the main repository can pull them via:

```bash
python inoue.py update
```

This automatically fetches and applies:
- New fingerprints added to `fingerprints/signatures.py`
- Updated scanner logic in `core/scanner.py`
- Bug fixes and performance improvements

## 4. Validate changes

Before contributing or after making local modifications, run validation checks:

### Run the test suite

```bash
python -m unittest discover -s tests -p 'test*.py' -q
```

### Verify Python modules compile

```bash
python -m compileall core fingerprints inoue.py
```

### Test a signature manually

```bash
# Test against a known service
python inoue.py https://alhamrizvi.in -e

# Verify version detection
python inoue.py https://alhamrizvi.in -v -e
```

### Check for common issues

- **Regex errors**: Test your regex patterns before committing
- **Import issues**: Ensure all referenced modules are imported
- **Indentation**: Python is sensitive to indentation; use 4 spaces
- **Key consistency**: Signature keys must match the defined schema

## 5. Repository structure for contributors

Understanding the project structure helps when contributing:

```
Inoue/
├── inoue.py                      # Main CLI entry point and update command
├── core/
│   ├── scanner.py               # Detection engine and version extraction
│   └── __init__.py
├── fingerprints/
│   ├── signatures.py            # Main catalog (700+ core signatures)
│   ├── extended_catalog.py       # Extended catalog for niche services
│   └── __init__.py
├── tests/
│   ├── test_scanner.py          # Unit tests for scanner logic
│   └── __init__.py
├── requirements.txt             # Python dependencies
├── pyproject.toml               # Project configuration
├── GUIDE.md                     # This file
├── CONTRIBUTING.md              # Contribution guidelines
├── COMMANDS.md                  # CLI reference
└── README.md                    # Project overview
```

### Key files for different contribution types

| Contribution Type | Primary File | Secondary Files |
|-------------------|-------------|-----------------|
| Add fingerprints | `fingerprints/signatures.py` | `tests/test_scanner.py` |
| Extend catalog | `fingerprints/extended_catalog.py` | N/A |
| Improve detection | `core/scanner.py` | `tests/test_scanner.py` |
| Bug fix | Relevant module | `tests/test_scanner.py` |
| Documentation | `GUIDE.md` or `CONTRIBUTING.md` | N/A |
