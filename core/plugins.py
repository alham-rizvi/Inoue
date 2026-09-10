# Copyright (c) 2026 Alham Rizvi. All rights reserved.
# Proprietary and confidential. Unauthorized copying, redistribution, modification,
# commercial use, or public disclosure is prohibited without written permission.
"""Discovery and execution for optional recon result plugins."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from core.scanner import ScanResult


def default_plugin_directories() -> list[Path]:
    repository_modules = Path(__file__).resolve().parent.parent / "modules"
    user_modules = Path.home() / ".config" / "inoue" / "modules"
    return [repository_modules, user_modules]


def run_plugins(
    result: ScanResult,
    directories: Optional[list[str | Path]] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> dict:
    outputs = {}
    paths = [Path(path) for path in directories] if directories else default_plugin_directories()
    for directory in paths:
        if not directory.is_dir():
            continue
        for plugin_path in sorted(directory.glob("*.py")):
            if plugin_path.name.startswith("_"):
                continue
            plugin_name = plugin_path.stem
            try:
                spec = importlib.util.spec_from_file_location(f"inoue_plugin_{plugin_name}", plugin_path)
                if not spec or not spec.loader:
                    raise ImportError("unable to load plugin")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                runner = getattr(module, "run", None)
                if not callable(runner):
                    raise TypeError("plugin must define run(result)")
                output = runner(result)
                try:
                    json.dumps(output)
                except (TypeError, ValueError) as exc:
                    raise TypeError(f"plugin output is not JSON serializable: {exc}") from exc
                outputs[plugin_name] = output
                if progress:
                    progress(f"plugin {plugin_name} completed")
            except Exception as exc:
                outputs[plugin_name] = {"error": str(exc)}
                if progress:
                    progress(f"plugin {plugin_name} failed: {exc}")
    return outputs
