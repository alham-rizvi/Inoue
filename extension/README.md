# Inoue Web Stack Detector

This shared WebExtension works in Chrome and Firefox. It reads the active HTTP(S) tab and asks a running Inoue Python API to perform a fast, read-only technology scan. Its presentation is inspired by the useful parts of Wappalyzer's workflow: grouped technology categories, confidence, versions, evidence, and vulnerability context, while using Inoue's Python catalog and original UI/code.

## Run locally

From the repository root, make sure the API dependencies are installed
(they're included in `requirements.txt`; if you installed the `inoue`
package directly instead, use `pip install "inoue[api]"`):

```bash
pip install -r requirements.txt
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

You should see `Uvicorn running on http://127.0.0.1:8000` - if instead
you get `ModuleNotFoundError: No module named 'fastapi'`, the API
dependencies weren't installed; run the `pip install` line above first.

Load `extension/` as an unpacked extension:

- Chrome: `chrome://extensions` -> Developer mode -> Load unpacked
- Firefox: `about:debugging#/runtime/this-firefox` -> Load Temporary Add-on -> select `manifest.json`

Open the popup, expand **Python API settings** if the API URL or API key differs from the defaults, and select **Detect stack**. Configuring a remote API asks the browser for permission to contact that origin.

## Release archives

```bash
python scripts/build_extension.py
```

The command writes `dist/extension/inoue-web-stack-detector-chrome-1.0.0.zip` and the corresponding Firefox archive. No API keys are bundled.
