# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""
Append-only scan history store.

`core.cache.ScanCache` intentionally keeps only the most recent result per
(target, module) - it's a cache, not a record. This module is a separate,
opt-in, append-only SQLite log of full scan snapshots per target, so users
can see how a target's tech stack, CVEs, ports, and certificates changed
over time (the same idea BuiltWith sells as "technology history", done
locally and offline).

Nothing here runs automatically: a snapshot is only ever written when the
caller explicitly asks for it (`--save-history` on the CLI, or
`save_history=True` on the API), matching the project's existing
"explicit, never silent" stance on writes (see CVE refresh, cache).
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

DEFAULT_HISTORY_PATH = "~/.cache/inoue/history.db"


def _connect(path: str) -> sqlite3.Connection:
    resolved = Path(path).expanduser()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(resolved)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS history ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "target TEXT NOT NULL, "
        "scanned_at REAL NOT NULL, "
        "payload TEXT NOT NULL"
        ")"
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_history_target ON history (target, scanned_at)")
    connection.commit()
    return connection


def record_snapshot(path: str, target: str, payload: dict) -> None:
    """Append a serialized scan result snapshot for `target`."""
    connection = _connect(path)
    try:
        connection.execute(
            "INSERT INTO history (target, scanned_at, payload) VALUES (?, ?, ?)",
            (target, time.time(), json.dumps(payload, separators=(",", ":"))),
        )
        connection.commit()
    finally:
        connection.close()


def list_snapshots(path: str, target: str, limit: int = 20) -> list[dict]:
    """Return up to `limit` snapshots for `target`, oldest first."""
    connection = _connect(path)
    try:
        rows = connection.execute(
            "SELECT scanned_at, payload FROM history WHERE target = ? ORDER BY scanned_at DESC LIMIT ?",
            (target, max(1, limit)),
        ).fetchall()
    finally:
        connection.close()
    snapshots = []
    for scanned_at, payload in rows:
        try:
            snapshots.append({"scanned_at": scanned_at, "result": json.loads(payload)})
        except json.JSONDecodeError:
            continue
    snapshots.reverse()  # oldest first
    return snapshots


def build_timeline(path: str, target: str, limit: int = 20) -> list[dict]:
    """Return a list of {from, to, diff} entries across stored snapshots."""
    from core.scanner import _deserialize_scan_result, diff_scan_results  # local import avoids a cycle

    snapshots = list_snapshots(path, target, limit=limit)
    timeline = []
    for previous, current in zip(snapshots, snapshots[1:]):
        prev_result = _deserialize_scan_result(previous["result"])
        curr_result = _deserialize_scan_result(current["result"])
        timeline.append({
            "from": previous["scanned_at"],
            "to": current["scanned_at"],
            "diff": diff_scan_results(prev_result, curr_result),
        })
    return timeline


def clear_history(path: str, target: Optional[str] = None) -> None:
    connection = _connect(path)
    try:
        if target:
            connection.execute("DELETE FROM history WHERE target = ?", (target,))
        else:
            connection.execute("DELETE FROM history")
        connection.commit()
    finally:
        connection.close()
