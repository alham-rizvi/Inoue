# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""TOML configuration loading with project-over-user precedence."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 fallback
    import tomli as tomllib


def _read(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as stream:
        payload = tomllib.load(stream)
    return payload if isinstance(payload, dict) else {}


def load_config(
    project_path: Optional[str] = None,
    user_path: Optional[str] = None,
) -> dict[str, Any]:
    user = Path(user_path).expanduser() if user_path else Path.home() / ".config" / "inoue" / "config.toml"
    project = Path(project_path) if project_path else Path.cwd() / ".inoue.toml"
    merged = _read(user)
    merged.update(_read(project))
    return merged
