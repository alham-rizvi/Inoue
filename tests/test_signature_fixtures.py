import json
from pathlib import Path

from core.scanner import run_fingerprints


FIXTURES = Path(__file__).parent / "fixtures"


def test_signature_fixtures_detect_expected_technology():
    fixture_dirs = sorted(path for path in FIXTURES.iterdir() if path.is_dir())
    assert fixture_dirs

    for fixture_dir in fixture_dirs:
        headers = json.loads((fixture_dir / "headers.json").read_text(encoding="utf-8"))
        body = (fixture_dir / "response.html").read_text(encoding="utf-8")
        detected = {item.name for item in run_fingerprints(headers, {}, body)}
        assert fixture_dir.name in detected, f"{fixture_dir.name} was not detected: {sorted(detected)}"
