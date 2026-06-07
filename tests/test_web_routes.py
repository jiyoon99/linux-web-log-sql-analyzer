import asyncio
from pathlib import Path
import tempfile
import unittest

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None

from linux_web_log_sql_analyzer.database import ingest_file, ingest_sql_file, init_db, managed_connect
from linux_web_log_sql_analyzer.web import create_app


@unittest.skipIf(httpx is None, "HTTP test dependencies are not installed")
class WebRoutesTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        asyncio.get_running_loop().slow_callback_duration = 1.0

    async def test_health_and_access_log_api_routes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "logs.db"
            sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
            with managed_connect(db_path) as conn:
                init_db(conn)
                ingest_file(conn, sample)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app(str(db_path))),
                base_url="http://testserver",
            ) as client:
                health = await client.get("/health")
                logs = await client.get("/api/v1/logs", params={"status": "401", "limit": "-1"})
                invalid = await client.get("/api/v1/logs", params={"status": "abc"})
                unknown = await client.get("/api/not-a-report")
                parse_errors = await client.get("/api/v1/metrics/parse-errors")

        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json(), {"status": "ok"})
        self.assertEqual(logs.status_code, 200)
        self.assertEqual(len(logs.json()), 1)
        self.assertEqual(logs.json()[0]["status"], 401)
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(unknown.status_code, 200)
        self.assertEqual(unknown.json(), [])
        self.assertEqual(parse_errors.status_code, 200)
        self.assertEqual(len(parse_errors.json()), 1)
        self.assertEqual(parse_errors.json()[0]["log_type"], "access")

    async def test_sql_log_api_route_filters(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "logs.db"
            sample = Path(__file__).resolve().parents[1] / "samples" / "sql-execution.log"
            with managed_connect(db_path) as conn:
                init_db(conn)
                ingest_sql_file(conn, sample)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=create_app(str(db_path))),
                base_url="http://testserver",
            ) as client:
                response = await client.get(
                    "/api/v1/sql-logs",
                    params={"statement_type": "SELECT", "min_duration_ms": "100"},
                )
                invalid = await client.get("/api/v1/sql-logs", params={"min_duration_ms": "slow"})
                parse_errors = await client.get("/api/v1/metrics/parse-errors")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()), 2)
        self.assertTrue(all(row["statement_type"] == "SELECT" for row in response.json()))
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(parse_errors.status_code, 200)
        self.assertEqual(len(parse_errors.json()), 1)
        self.assertEqual(parse_errors.json()[0]["log_type"], "sql")


if __name__ == "__main__":
    unittest.main()
