import json
from pathlib import Path

from core.scanner import run_fingerprints
from scripts.audit_signatures import audit_signatures


FIXTURES = Path(__file__).parent / "fixtures"


def test_signature_fixtures_detect_expected_technology():
    fixture_dirs = sorted(path for path in FIXTURES.iterdir() if path.is_dir())
    assert fixture_dirs

    for fixture_dir in fixture_dirs:
        headers = json.loads((fixture_dir / "headers.json").read_text(encoding="utf-8"))
        body = (fixture_dir / "response.html").read_text(encoding="utf-8")
        detected = {item.name for item in run_fingerprints(headers, {}, body)}
        assert fixture_dir.name in detected, f"{fixture_dir.name} was not detected: {sorted(detected)}"


def test_signature_audit_reports_missing_and_stale_provenance():
    findings = audit_signatures(
        {
            "Current": {"source": "manual", "since": "2026-01-01", "last_verified": "2026-09-01"},
            "Missing": {"source": "community"},
            "Stale": {"source": "manual", "last_verified": "2024-01-01"},
        },
        stale_days=30,
        today=__import__("datetime").date(2026, 9, 9),
    )

    by_name = {finding["name"]: finding["reason"] for finding in findings}
    assert "Missing" in by_name
    assert "Stale" in by_name
    assert "Current" not in by_name
