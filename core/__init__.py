"""Core library modules for the Inoue scanner.

Each module owns one slice of the pipeline - ``scanner`` drives detection,
``scope`` gates targets, ``waf``/``http_posture``/``security_grade`` grade the
HTTP surface, ``js_intel``/``api_discovery``/``takeover`` cover the JavaScript
and DNS attack surface, ``cve``/``risk`` handle vulnerability awareness and
ranking, and ``history``/``webhooks``/``cache`` handle persistence and
delivery. Nothing in this package performs network I/O at import time, so it
is safe to import from the CLI, the optional FastAPI app and the MCP server.
"""
