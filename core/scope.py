"""Scope and safety controls for authorized, read-only recon."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import threading
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(ValueError):
    """Raised when a target is outside an explicitly supplied scope."""


class RequestBudget:
    def __init__(self, maximum: int | None = None):
        self.maximum = None if maximum is None or maximum <= 0 else int(maximum)
        self.used = 0
        self._lock = threading.Lock()

    def consume(self, count: int = 1) -> bool:
        with self._lock:
            if self.maximum is not None and self.used + count > self.maximum:
                return False
            self.used += count
            return True

    @property
    def remaining(self) -> int | None:
        return None if self.maximum is None else max(0, self.maximum - self.used)


def _load_document(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        # Deliberately small YAML subset: lists under allow/deny and scalar keys.
        data: dict[str, list[str] | str] = {}
        current: str | None = None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if line.endswith(":"):
                current = line[:-1].strip()
                data[current] = []
            elif line.startswith("-") and current:
                assert isinstance(data[current], list)
                data[current].append(line[1:].strip().strip("'\""))
            elif ":" in line:
                key, value = line.split(":", 1)
                data[key.strip()] = value.strip().strip("'\"")
        return data


class ScopeMatcher:
    def __init__(self, allow: list[str] | None = None, deny: list[str] | None = None):
        self.allow = [str(item).lower().rstrip(".") for item in (allow or [])]
        self.deny = [str(item).lower().rstrip(".") for item in (deny or [])]

    @classmethod
    def from_file(cls, path: str | None) -> "ScopeMatcher | None":
        if not path:
            return None
        data = _load_document(path)
        allow = data.get("allow", data.get("in_scope", data.get("targets", [])))
        deny = data.get("deny", data.get("out_of_scope", data.get("exclude", [])))
        def as_list(value):
            return value if isinstance(value, list) else [value] if value else []
        return cls(as_list(allow), as_list(deny))

    def _matches(self, host: str, pattern: str) -> bool:
        host = host.lower().rstrip(".")
        pattern = pattern.lower().strip().rstrip(".")
        try:
            address = ipaddress.ip_address(host)
            if "/" in pattern:
                return address in ipaddress.ip_network(pattern, strict=False)
            return host == pattern
        except ValueError:
            pass
        if pattern.startswith("*."):
            suffix = pattern[1:]
            return host.endswith(suffix) and host != suffix[1:]
        return fnmatch.fnmatchcase(host, pattern) or host == pattern

    def check(self, target: str) -> bool:
        host = urlparse(target if "://" in target else f"https://{target}").hostname or target
        if any(self._matches(host, item) for item in self.deny):
            return False
        return not self.allow or any(self._matches(host, item) for item in self.allow)

    def require(self, target: str) -> None:
        if not self.check(target):
            raise ScopeError(f"target is outside configured scope: {target}")


def init_scope_document(program_url: str, output_path: str) -> str:
    """Write a conservative starter scope file; never treats fetched content as authorization."""
    content = f"# Review against the program policy before scanning.\nprogram: {program_url}\nallow:\n  - example.com\ndeny:\n  - '*.internal.example.com'\n  - 10.0.0.0/8\n"
    Path(output_path).write_text(content, encoding="utf-8")
    return output_path
