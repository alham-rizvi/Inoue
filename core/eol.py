# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Technology end-of-life (EOL) detection.

Cross-references a detected technology + version against a static table
of verified EOL dates. Running EOL software means no further security
patches - a real, concrete, frequently-reported bug bounty and pentest
finding, and one Inoue can now surface automatically the moment a
version is captured (which the aggressive version hunter makes far more
likely than before).

Every date below was verified against the vendor's own support-lifecycle
page as of this build (PHP: php.net/supported-versions.php, Node.js and
Python: endoflife.date, cross-checked against vendor announcements).
This is a **static table that will go stale** - it is not a live feed.
Only technologies with day-level dates from an authoritative source are
included; nothing here is guessed or extrapolated. Absence from this
table means "not checked", never "not EOL".
"""

from __future__ import annotations

from datetime import date
from typing import Optional

# name -> list of (major.minor prefix, eol_date, source_note)
# Sorted newest-first within each technology; the first prefix match wins.
_EOL_TABLE: dict[str, list[tuple[str, date, str]]] = {
    "PHP": [
        ("8.4", date(2028, 12, 31), "php.net/supported-versions.php"),
        ("8.3", date(2027, 12, 31), "php.net/supported-versions.php"),
        ("8.2", date(2026, 12, 31), "php.net/supported-versions.php"),
        ("8.1", date(2025, 12, 31), "php.net/supported-versions.php"),
        ("8.0", date(2023, 11, 26), "php.net/supported-versions.php"),
        ("7.4", date(2022, 11, 28), "php.net/supported-versions.php"),
        ("7.3", date(2021, 12, 6), "php.net/supported-versions.php"),
        ("7.2", date(2020, 11, 30), "php.net/supported-versions.php"),
        ("7.1", date(2019, 12, 1), "php.net/supported-versions.php"),
        ("7.0", date(2018, 12, 3), "php.net/supported-versions.php"),
        ("5.6", date(2018, 12, 31), "php.net/supported-versions.php"),
    ],
    "Node.js": [
        ("24", date(2028, 4, 30), "endoflife.date/nodejs"),
        ("22", date(2027, 4, 30), "endoflife.date/nodejs"),
        ("21", date(2024, 6, 1), "endoflife.date/nodejs"),
        ("20", date(2026, 4, 30), "endoflife.date/nodejs"),
        ("19", date(2023, 6, 1), "endoflife.date/nodejs"),
        ("18", date(2025, 4, 30), "endoflife.date/nodejs"),
        ("17", date(2022, 6, 1), "endoflife.date/nodejs"),
        ("16", date(2023, 9, 11), "endoflife.date/nodejs"),
        ("14", date(2023, 4, 30), "endoflife.date/nodejs"),
        ("12", date(2022, 4, 30), "endoflife.date/nodejs"),
    ],
    "Python": [
        ("3.13", date(2029, 10, 31), "endoflife.date/python"),
        ("3.12", date(2028, 10, 31), "endoflife.date/python"),
        ("3.11", date(2027, 10, 31), "endoflife.date/python"),
        ("3.10", date(2026, 10, 31), "endoflife.date/python"),
        ("3.9", date(2025, 10, 31), "endoflife.date/python"),
        ("3.8", date(2024, 10, 7), "endoflife.date/python"),
        ("3.7", date(2023, 6, 27), "endoflife.date/python"),
        ("3.6", date(2021, 12, 23), "endoflife.date/python"),
        ("2.7", date(2020, 1, 1), "endoflife.date/python"),
    ],
}

# Some signatures report the runtime under a different name than the
# table key (e.g. the "Python" signature vs. a Django app implying it).
_ALIASES = {"php": "PHP", "node.js": "Node.js", "nodejs": "Node.js", "node": "Node.js", "python": "Python"}


def _lookup(name: str, version: str) -> Optional[tuple[date, str]]:
    table_key = _ALIASES.get(name.lower(), name)
    entries = _EOL_TABLE.get(table_key)
    if not entries or not version:
        return None

    parts = version.split(".")
    for prefix, eol_date, source in entries:
        prefix_parts = prefix.split(".")
        if parts[: len(prefix_parts)] == prefix_parts:
            return eol_date, source
    return None


def check_eol(name: str, version: str, as_of: Optional[date] = None) -> Optional[dict]:
    """Check one technology+version against the EOL table.

    Returns None when the technology/version isn't in the table (not "not
    EOL" - just "not checked"), so callers must not treat a None result as
    a clean bill of health.
    """
    found = _lookup(name, version)
    if not found:
        return None
    eol_date, source = found

    reference = as_of or date.today()
    is_eol = reference >= eol_date
    days_delta = (reference - eol_date).days

    return {
        "name": name,
        "version": version,
        "eol_date": eol_date.isoformat(),
        "is_eol": is_eol,
        "days_past_eol": days_delta if is_eol else None,
        "days_until_eol": -days_delta if not is_eol else None,
        "source": source,
    }


def check_technologies(technologies: list, as_of: Optional[date] = None) -> list[dict]:
    """Check every detected technology that has a version against the EOL
    table. `technologies` is a list of Detection-like objects with .name
    and .version attributes."""
    findings = []
    for tech in technologies or []:
        version = getattr(tech, "version", None)
        name = getattr(tech, "name", None)
        if not version or not name:
            continue
        result = check_eol(name, version, as_of=as_of)
        if result and result["is_eol"]:
            findings.append(result)
    return findings
