import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from core.scanner import Detection, ScanResult
from api.main import BatchRequest, ScanRequest, create_app


class ApiBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        if cls.app is None:
            raise unittest.SkipTest("FastAPI is not installed")
        cls.routes = {route.path: route.endpoint for route in cls.app.routes if hasattr(route, "endpoint")}

    def test_request_models_reject_unsafe_bounds(self):
        with self.assertRaises(Exception):
            ScanRequest(target="example.com", timeout=0)
        with self.assertRaises(Exception):
            BatchRequest(targets=["example.com"], workers=0)
        with self.assertRaises(Exception):
            BatchRequest(targets=["example.com"], rate_limit=0)

    def test_single_scan_runs_in_worker_and_returns_complete_result(self):
        expected = ScanResult(
            url="https://example.com",
            final_url="https://example.com/",
            status_code=200,
            response_time_ms=4.2,
            ip="192.0.2.1",
            dns_records={"A": ["192.0.2.1"]},
            technologies=[Detection("Nginx", "Web Server", version="1.26.0")],
        )

        async def run():
            with patch("api.main.scan", return_value=expected) as mocked_scan:
                response = await self.routes["/scan"](ScanRequest(target="example.com"))
            mocked_scan.assert_called_once_with(
                "example.com",
                timeout=10,
                follow_redirects=True,
                modules=None,
                cve_min_severity=None,
            )
            return response

        payload = asyncio.run(run())
        self.assertEqual(payload["ip"], "192.0.2.1")
        self.assertEqual(payload["dns"], {"A": ["192.0.2.1"]})
        self.assertEqual(payload["technologies"][0]["name"], "Nginx")

    def test_batch_scan_returns_same_result_contract(self):
        result = ScanResult(
            url="https://example.com",
            final_url="https://example.com/",
            status_code=200,
            response_time_ms=1.0,
        )

        async def run():
            with patch("api.main.scan_many", new=AsyncMock(return_value=[result])) as mocked_scan_many:
                response = await self.routes["/scan/batch"](BatchRequest(targets=["example.com"]))
            mocked_scan_many.assert_awaited_once()
            return response

        payload = asyncio.run(run())
        self.assertEqual(len(payload["results"]), 1)
        self.assertIn("final_url", payload["results"][0])
        self.assertIn("extra_intel", payload["results"][0])


if __name__ == "__main__":
    unittest.main()
