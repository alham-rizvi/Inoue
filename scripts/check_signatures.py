#!/usr/bin/env python3
"""Report duplicate literal keys in the SIGNATURES dictionary."""

import ast
import pprint
import sys
from pathlib import Path


SIGNATURE_FILE = Path(__file__).resolve().parents[1] / "fingerprints" / "signatures.py"


def find_duplicates(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    duplicates = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if "SIGNATURES" not in names or not isinstance(node.value, ast.Dict):
            continue
        seen = set()
        for key in node.value.keys:
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if key.value in seen:
                    duplicates.append(key.value)
                seen.add(key.value)
    return duplicates


def merge_values(current, incoming):
    if isinstance(current, list) and isinstance(incoming, list):
        return current + [item for item in incoming if item not in current]
    if isinstance(current, dict) and isinstance(incoming, dict):
        merged = dict(current)
        for key, value in incoming.items():
            merged[key] = merge_values(merged[key], value) if key in merged else value
        return merged
    return incoming


def rewrite_merged_catalog(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        if "SIGNATURES" not in names or not isinstance(node.value, ast.Dict):
            continue
        merged = {}
        for key, value in zip(node.value.keys, node.value.values):
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                raise ValueError("SIGNATURES contains a non-literal key")
            merged[key.value] = merge_values(merged.get(key.value, {}), ast.literal_eval(value))
        replacement = "SIGNATURES = " + pprint.pformat(merged, width=120, sort_dicts=False)
        start = node.lineno - 1
        end = node.end_lineno
        lines = source.splitlines()
        path.write_text("\n".join(lines[:start] + [replacement] + lines[end:]) + "\n", encoding="utf-8")
        return
    raise ValueError("SIGNATURES assignment not found")


def main() -> int:
    if "--rewrite" in sys.argv[1:]:
        rewrite_merged_catalog(SIGNATURE_FILE)
    duplicates = find_duplicates(SIGNATURE_FILE)
    if duplicates:
        for key in duplicates:
            print(f"duplicate signature key: {key}")
        return 1
    print(f"no duplicate signature keys found in {SIGNATURE_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
