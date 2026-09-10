"""User-editable Rich terminal presentation settings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console


DEFAULT_COLORS = {
    "Web Server": "cyan",
    "Language": "green",
    "Framework": "bright_green",
    "CMS": "yellow",
    "JS Framework": "bright_blue",
    "JS Library": "blue",
    "CDN / Security": "red",
    "CDN": "bright_red",
    "WAF": "bright_red",
    "Database": "bright_cyan",
    "Other": "white",
}


@dataclass(frozen=True)
class TerminalSettings:
    text_style: str = "default"
    layout: str = "standard"
    colors: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_COLORS))

    @property
    def table_geometry(self) -> dict[str, object]:
        if self.layout == "compact":
            return {"category": 14, "technology": 18, "version": 10, "padding": (0, 1, 0, 0)}
        if self.layout == "wide":
            return {"category": 24, "technology": 30, "version": 16, "padding": (0, 3, 0, 0)}
        return {"category": 20, "technology": 22, "version": 14, "padding": (0, 2, 0, 0)}


def load_terminal_settings(config: dict[str, Any] | None = None) -> TerminalSettings:
    values = (config or {}).get("terminal", {})
    if not isinstance(values, dict):
        values = {}
    layout = values.get("layout", "standard")
    if layout not in {"compact", "standard", "wide"}:
        layout = "standard"
    text_style = values.get("text_style", "default")
    if not isinstance(text_style, str) or not text_style.strip():
        text_style = "default"
    colors = dict(DEFAULT_COLORS)
    configured_colors = values.get("colors", {})
    if isinstance(configured_colors, dict):
        colors.update({str(key): str(value) for key, value in configured_colors.items() if value})
    return TerminalSettings(text_style=text_style, layout=layout, colors=colors)


def create_console(settings: TerminalSettings) -> Console:
    return Console(style=settings.text_style)
