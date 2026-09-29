"""Signature catalogs for technology fingerprinting.

``signatures`` holds the compiled live catalog, ``modern_catalog`` and
``extended_catalog`` contribute imported/curated entries, and
``web_server_catalog`` and ``favicon_hashes`` cover server families and
favicon hashes respectively. Detection code in ``core.scanner`` consumes these
tables; nothing here performs network I/O.
"""
