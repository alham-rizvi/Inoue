# Contributing to Inoue

Thanks for helping improve Inoue. This guide explains how to contribute fingerprints, improvements, and features.

## Ways to contribute

- **Report bugs and feature requests** via GitHub issues
- **Improve fingerprinting signatures** by adding new services or refining detection patterns
- **Add support for more technologies** (frameworks, CMS platforms, cloud services, admin panels, etc.)
- **Improve detection heuristics** for better version extraction and matching accuracy
- **Improve docs and examples** to help other contributors

## Development setup

### Clone and prepare environment

```bash
git clone https://github.com/alhamrizvi-cloud/Inoue.git
cd Inoue
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Verify setup

```bash
# Test the CLI
python inoue.py --help

# Run the test suite
python -m unittest discover -s tests -p 'test*.py' -q

# Verify modules compile
python -m compileall core fingerprints inoue.py
```

## Types of contributions

### 1. Adding new fingerprints

This is the most common contribution. Follow this process:

1. **Identify a service** that isn't yet detected (check `fingerprints/signatures.py` first)
2. **Research detection patterns**:
   - Check HTTP headers: `curl -i https://example.com | grep -i server`
   - Inspect HTML: Check page source for meta tags, comments, or distinctive strings
   - Look for script sources and paths: `/api/v1/`, `/admin`, etc.
3. **Add to signatures.py**:
   ```python
   "MyService": {
       "category": "Web Server",  # or appropriate category
       "headers": {"Server": r"MyService/([0-9.]+)?"},
       "html": [r"Powered by MyService", r"<!--.*MyService.*-->"],
       "paths": [r"/admin", r"/config"],
   }
   ```
4. **Test locally**: `python inoue.py https://example.com -e`
5. **Run test suite**: `python -m unittest discover -s tests -p 'test*.py' -q`

#### Fixture-based signature tests

Every new high-traffic signature should include a fixture directory under
`tests/fixtures/<Technology Name>/` with:

- `response.html` containing the smallest representative response signal
- `headers.json` containing representative response headers, or `{}`

The parametrized harness in `tests/test_signature_fixtures.py` discovers these
directories automatically and asserts that the directory name is detected.
Use indexed signals such as a distinctive script source, header, or HTML token;
the tokenizer and signature indexes intentionally filter weak candidates.
Run the focused harness with:

```bash
python -m pytest tests/test_signature_fixtures.py -q
```

### 2. Improving version detection

Enhance how versions are extracted from services:

1. **Use regex capture groups** in headers:
   ```python
   "headers": {"Server": r"Service(?:/v?([0-9.]+))?"}
   ```
2. **Add multiple patterns** for flexibility:
   ```python
   "html": [
       r"Version: ([0-9.]+)",
       r"<!--\s*Version ([0-9.]+)\s*-->",
       r"data-version=\"([0-9.]+)\"",
   ]
   ```
3. **Test version extraction**: Run scanner in verbose mode to verify versions are captured

### 3. Extending the catalog

For niche or regional services, use `fingerprints/extended_catalog.py`:

```python
EXTENDED_SIGNATURES = {
    "RegionalService": {
        "category": "CRM / Chat",
        "html": [r"RegionalService Dashboard"],
    },
    ...
}
```

### 4. Scanner improvements

If you improve detection logic in `core/scanner.py`:

1. **Add tests** in `tests/test_scanner.py` for your new logic
2. **Include comments** explaining the heuristic
3. **Verify backward compatibility** by running full test suite
4. **Document the improvement** in your PR description

### 5. Bug fixes

When fixing bugs:

1. **Create a test case** that reproduces the bug
2. **Fix the code** in the relevant module
3. **Verify the test passes** after the fix
4. **Add a comment** in your PR explaining the root cause

## Files involved in the update mechanism

When you submit a PR, understand how your changes are distributed:

| File | Fetched via `update`? | Impact | Who should edit? |
|------|----------------------|--------|-----------------|
| `fingerprints/signatures.py` | ✅ Yes | New/updated service signatures | Contributors, maintainers |
| `fingerprints/extended_catalog.py` | ✅ Yes | Extended catalog for niche services | Contributors, maintainers |
| `core/scanner.py` | ✅ Yes | Core detection engine improvements | Maintainers primarily |
| `tests/test_scanner.py` | ✅ Yes | Test suite for validation | Contributors, maintainers |
| `inoue.py` | ✅ Yes | CLI and command updates | Maintainers primarily |
| `GUIDE.md`, `CONTRIBUTING.md` | ✅ Yes | Documentation updates | Contributors, maintainers |
| `requirements.txt` | ✅ Yes | Dependency updates | Maintainers |
| `.gitignore`, other config | ✅ Yes | Repository configuration | Maintainers |

**Key point**: When you contribute to `fingerprints/signatures.py`, your changes automatically reach all users via `python inoue.py update`.

## Signature best practices

### Category usage

Use these categories for consistency:

- Web servers: `Apache`, `Nginx`, `IIS`, etc. → category: `"Web Server"`
- Frameworks: `Laravel`, `Django`, `Express` → category: `"Framework"`
- CMS: `WordPress`, `Drupal` → category: `"CMS"` or `"CMS / E-Commerce"`
- Cloud services: `AWS`, `Azure`, `GCP portals` → category: `"Cloud"`
- Admin panels: `phpMyAdmin`, `pgAdmin` → category: `"Admin Panel"`
- Ecommerce: `Magento`, `Shopify` → category: `"E-Commerce"`

### Regex pattern tips

- **Use raw strings**: `r"pattern"` to avoid escaping backslashes
- **Use non-capturing groups**: `r"(?:variant1|variant2)"` to avoid adding capture groups
- **Use word boundaries**: `r"\bServiceName\b"` to avoid false positives
- **Case insensitive**: Patterns are matched case-insensitively
- **Test your regex**: Use an online regex tester before committing

**Example**:
```python
"WordPress": {
    "category": "CMS",
    "html": [
        r"wp-content/plugins",      # Distinctive path
        r"WordPress\s+(?:CMS\s+)?v?([0-9.]+)?",  # Version capture
        r"Powered by WordPress",
    ],
    "headers": {
        "X-Powered-By": r"WordPress",
    }
}
```

## Pull request checklist

Before submitting your PR:

- [ ] Changes are focused (one feature or category, not mixed)
- [ ] Code is well documented (comments for complex logic)
- [ ] Regex patterns are tested and don't produce false positives
- [ ] CLI still runs: `python inoue.py --help` ✅
- [ ] Test suite passes: `python -m unittest discover -s tests -p 'test*.py' -q` ✅
- [ ] Modules compile: `python -m compileall core fingerprints inoue.py` ✅
- [ ] New signatures are tested manually: `python inoue.py <target> -e` ✅
- [ ] PR has clear description of what changed and why
- [ ] If adding signatures, include examples/evidence (links, screenshots, curl output)

## Commit message guidelines

Write clear, descriptive commit messages:

```
Add Kubernetes Admin Portal fingerprint

- Add detection for Kubernetes Dashboard
- Version detection from kube-apiserver header
- Tested against k8s 1.20 and 1.24
```

Rather than:

```
update signatures
```

## Questions or stuck?

- Check existing issues and PRs for similar problems
- Review the [GUIDE.md](GUIDE.md) for detailed technical documentation
- Ask in the PR or create a discussion issue
- Reach out to the maintainers for guidance on complex changes

## After your PR is merged

When your PR is merged to `main`:

1. Users can immediately see your changes in the repository
2. Users who run `python inoue.py update` will fetch your changes
3. Your contribution is part of the fingerprint catalog for all users

Thank you for contributing! 🎉
