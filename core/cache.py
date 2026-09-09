# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""Small opt-in SQLite cache for repeatable scan results."""

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional


class ScanCache:
    def __init__(self, path: str, ttl: int = 86400):
        self.path = Path(path).expanduser()
        self.ttl = max(0, ttl)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS cache (target TEXT NOT NULL, module TEXT NOT NULL, created REAL NOT NULL, payload TEXT NOT NULL, PRIMARY KEY (target, module))"
            )

    def get(self, target: str, module: str) -> Optional[dict]:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "SELECT created, payload FROM cache WHERE target = ? AND module = ?",
                (target, module),
            ).fetchone()
        if not row or time.time() - row[0] > self.ttl:
            return None
        try:
            return json.loads(row[1])
        except json.JSONDecodeError:
            return None

    def set(self, target: str, module: str, payload: dict) -> None:
        serialized = json.dumps(payload, separators=(",", ":"))
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                "INSERT OR REPLACE INTO cache (target, module, created, payload) VALUES (?, ?, ?, ?)",
                (target, module, time.time(), serialized),
            )

    def clear(self) -> None:
        with sqlite3.connect(self.path) as connection:
            connection.execute("DELETE FROM cache")
