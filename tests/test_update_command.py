"""Regression tests for the shadowed ``update`` subcommand.

``main`` is registered with ``@app.callback(invoke_without_command=True)`` and
declares a variadic ``targets`` argument, which swallows the first positional
token.  Typer therefore never routes to the registered ``update`` command, so
``about``, ``history``, ``update-cve`` and ``watch`` are all dispatched manually
inside ``main``.  ``update`` was missing from that dispatch and
``inoue update`` scanned a host literally named "update" (DNS NXDOMAIN) instead
of calling the self-update implementation.

These tests never touch the network and never perform a real update: the scan
entry point and the self-update entry point are both stubbed.
"""

import json
import unittest
from unittest.mock import patch

from typer.testing import CliRunner

from core.scanner import ScanResult
from inoue import app


def invoke_cli(args):
    """Invoke the CLI without the banner so stdout is only the command output."""
    return CliRunner().invoke(app, ["--no-banner"] + list(args), catch_exceptions=False)


class UpdateCommandTests(unittest.TestCase):
    """``update`` must be reachable, and must not be confused with a target."""

    def test_update_help_exits_zero_and_prints_usage(self):
        """`update --help` prints help instead of scanning a host named "update"."""
        with patch("inoue.run_self_update") as mock_update, patch("inoue.scan") as mock_scan:
            result = invoke_cli(["update", "--help"])

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Usage: python inoue.py update", result.stdout)
        # Help must neither perform an update nor scan anything.
        mock_update.assert_not_called()
        mock_scan.assert_not_called()
        self.assertNotIn("starting request", result.stdout)

    def test_update_dispatches_to_self_update_without_really_updating(self):
        """The dispatch reaches the self-update path, with the real update stubbed out."""
        stub = {"ok": True, "message": "Repository updated successfully", "details": ""}
        with patch("inoue.run_self_update", return_value=stub) as mock_update, patch("inoue.scan") as mock_scan:
            result = invoke_cli(["update"])

        self.assertEqual(result.exit_code, 0)
        mock_update.assert_called_once_with()
        mock_scan.assert_not_called()
        self.assertIn("updated", result.stdout)

    def test_plain_target_is_not_misrouted_to_update(self):
        """A normal target still goes through the scanner, not the update branch."""
        with patch("inoue.scan") as mock_scan, patch("inoue.run_self_update") as mock_update:
            mock_scan.return_value = ScanResult(
                url="https://example.com",
                final_url="https://example.com",
                status_code=200,
                response_time_ms=1.0,
            )
            result = invoke_cli(["example.com"])

        self.assertEqual(result.exit_code, 0)
        mock_update.assert_not_called()
        self.assertEqual(mock_scan.call_count, 1)
        self.assertIn("example.com", mock_scan.call_args[0][0])

    def test_unknown_update_option_exits_two(self):
        """Unknown update options are reported like the other manual dispatch branches."""
        with patch("inoue.run_self_update") as mock_update, patch("inoue.scan") as mock_scan:
            result = invoke_cli(["update", "--bogus"])

        self.assertEqual(result.exit_code, 2)
        self.assertIn("unknown update option", result.stdout)
        mock_update.assert_not_called()
        mock_scan.assert_not_called()

    def test_about_command_still_works(self):
        """The neighbouring manual dispatch branch is unaffected."""
        result = invoke_cli(["about", "--json"])

        self.assertEqual(result.exit_code, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["name"], "Inoue")
        self.assertIn("update", payload["commands"])


if __name__ == "__main__":
    unittest.main()
