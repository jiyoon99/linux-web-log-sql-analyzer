from pathlib import Path
import queue
import sqlite3
import tempfile
import threading
import unittest

from linux_web_log_sql_analyzer import analyzer
from linux_web_log_sql_analyzer.database import connect, ingest_file, ingest_sql_file, init_db, insert_log
from linux_web_log_sql_analyzer.parser import parse_access_log_line


class DatabaseTest(unittest.TestCase):
    def test_ingest_and_analyze_sample(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = sqlite3.connect(Path(tmpdir) / "logs.db")
            try:
                conn.row_factory = sqlite3.Row
                init_db(conn)

                parsed, failed, skipped = ingest_file(conn, sample)
                overview = analyzer.overview(conn)
                suspicious = analyzer.suspicious_ips(conn)
                login_logs = analyzer.search_access_logs(conn, path="/login", status=401)
            finally:
                conn.close()

        self.assertEqual(parsed, 9)
        self.assertEqual(failed, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual(overview["total"], 10)
        self.assertGreaterEqual(overview["client_errors"], 4)
        self.assertTrue(any(row["remote_addr"] == "198.51.100.8" for row in suspicious))
        self.assertEqual(len(login_logs), 2)

    def test_access_ingest_skips_existing_source_lines(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = sqlite3.connect(Path(tmpdir) / "logs.db")
            try:
                conn.row_factory = sqlite3.Row
                init_db(conn)

                first = ingest_file(conn, sample)
                second = ingest_file(conn, sample)
                overview = analyzer.overview(conn)
            finally:
                conn.close()

        self.assertEqual(first, (9, 1, 0))
        self.assertEqual(second, (0, 0, 10))
        self.assertEqual(overview["total"], 10)

    def test_access_ingest_skips_relative_absolute_same_file(self):
        relative_sample = Path("samples") / "nginx-access.log"
        absolute_sample = relative_sample.resolve()
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = sqlite3.connect(Path(tmpdir) / "logs.db")
            try:
                conn.row_factory = sqlite3.Row
                init_db(conn)

                first = ingest_file(conn, relative_sample)
                second = ingest_file(conn, absolute_sample)
                overview = analyzer.overview(conn)
            finally:
                conn.close()

        self.assertEqual(first, (9, 1, 0))
        self.assertEqual(second, (0, 0, 10))
        self.assertEqual(overview["total"], 10)

    def test_access_ingest_serializes_concurrent_writers(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
        results: queue.Queue[tuple[int, int, int] | Exception] = queue.Queue()

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "logs.db"

            def ingest_worker() -> None:
                conn = connect(db_path)
                try:
                    results.put(ingest_file(conn, sample))
                except Exception as exc:
                    results.put(exc)
                finally:
                    conn.close()

            threads = [threading.Thread(target=ingest_worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            conn = connect(db_path)
            try:
                overview = analyzer.overview(conn)
            finally:
                conn.close()

        worker_results = [results.get_nowait() for _ in range(2)]
        failures = [result for result in worker_results if isinstance(result, Exception)]
        self.assertEqual(failures, [])
        self.assertCountEqual(worker_results, [(9, 1, 0), (0, 0, 10)])
        self.assertEqual(overview["total"], 10)

    def test_ingest_and_analyze_sql_sample(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "sql-execution.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = sqlite3.connect(Path(tmpdir) / "logs.db")
            try:
                conn.row_factory = sqlite3.Row
                init_db(conn)

                parsed, failed, skipped = ingest_sql_file(conn, sample)
                overview = analyzer.sql_overview(conn)
                slow = analyzer.slow_sql(conn)
                sql_types = analyzer.sql_types(conn)
                filtered = analyzer.search_sql_logs(conn, statement_type="SELECT", min_duration_ms=100)
                limited = analyzer.slow_sql(conn, -1)
            finally:
                conn.close()

        self.assertEqual(parsed, 4)
        self.assertEqual(failed, 1)
        self.assertEqual(skipped, 0)
        self.assertEqual(overview["total"], 5)
        self.assertEqual(slow[0]["table_name"], "order_item")
        self.assertTrue(any(row["statement_type"] == "SELECT" for row in sql_types))
        self.assertEqual(len(filtered), 2)
        self.assertGreaterEqual(len(limited), 1)
        self.assertLessEqual(len(limited), analyzer.MAX_LIMIT)

    def test_sql_ingest_skips_existing_source_lines(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "sql-execution.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = sqlite3.connect(Path(tmpdir) / "logs.db")
            try:
                conn.row_factory = sqlite3.Row
                init_db(conn)

                first = ingest_sql_file(conn, sample)
                second = ingest_sql_file(conn, sample)
                overview = analyzer.sql_overview(conn)
            finally:
                conn.close()

        self.assertEqual(first, (4, 1, 0))
        self.assertEqual(second, (0, 0, 5))
        self.assertEqual(overview["total"], 5)

    def test_search_access_logs_filters_and_clamps_offset(self):
        lines = [
            '203.0.113.10 - - [04/Jun/2026:09:00:01 +0000] "GET /products?q=coffee HTTP/1.1" 200 1240 "-" "Mozilla/5.0"',
            '203.0.113.11 - - [04/Jun/2026:09:30:01 +0000] "POST /products/checkout HTTP/1.1" 201 640 "-" "Mozilla/5.0"',
            '203.0.113.12 - - [04/Jun/2026:10:00:01 +0000] "GET /admin HTTP/1.1" 500 20 "-" "curl/8"',
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            conn = sqlite3.connect(Path(tmpdir) / "logs.db")
            try:
                conn.row_factory = sqlite3.Row
                init_db(conn)
                for line_no, line in enumerate(lines, start=1):
                    insert_log(conn, parse_access_log_line(line, source="inline", line_no=line_no))
                conn.commit()

                method_rows = analyzer.search_access_logs(conn, method="post", path="checkout")
                time_rows = analyzer.search_access_logs(
                    conn,
                    from_time="2026-06-04T09:15:00+00:00",
                    to_time="2026-06-04T09:45:00+00:00",
                )
                offset_rows = analyzer.search_access_logs(conn, limit=2, offset=-10)
            finally:
                conn.close()

        self.assertEqual(len(method_rows), 1)
        self.assertEqual(method_rows[0]["method"], "POST")
        self.assertEqual(method_rows[0]["path"], "/products/checkout")
        self.assertEqual(len(time_rows), 1)
        self.assertEqual(time_rows[0]["remote_addr"], "203.0.113.11")
        self.assertEqual(len(offset_rows), 2)
        self.assertEqual(offset_rows[0]["remote_addr"], "203.0.113.12")


if __name__ == "__main__":
    unittest.main()
