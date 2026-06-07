from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from linux_web_log_sql_analyzer.cli import main


class CliTest(unittest.TestCase):
    def test_global_db_argument_is_used_before_summary_subcommand(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "global.db"

            ingest_code, _ = self._run_cli(["--db", str(db_path), "ingest", str(sample)])
            summary_code, output = self._run_cli(["--db", str(db_path), "summary"])

        self.assertEqual(ingest_code, 0)
        self.assertEqual(summary_code, 0)
        self.assertIn('"total": 10', output)

    def test_subcommand_db_argument_is_used_after_summary_subcommand(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "subcommand.db"

            ingest_code, _ = self._run_cli(["ingest", str(sample), "--db", str(db_path)])
            summary_code, output = self._run_cli(["summary", "--db", str(db_path)])

        self.assertEqual(ingest_code, 0)
        self.assertEqual(summary_code, 0)
        self.assertIn('"total": 10', output)

    def test_ingest_and_export_json_from_cli(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "logs.db"

            ingest_code, ingest_output = self._run_cli(["ingest", str(sample), "--db", str(db_path)])
            export_code, export_output = self._run_cli(
                ["export", "status", "--db", str(db_path), "--format", "json"]
            )
            parse_errors_code, parse_errors_output = self._run_cli(
                ["export", "parse-errors", "--db", str(db_path), "--format", "json"]
            )

        rows = json.loads(export_output)
        parse_error_rows = json.loads(parse_errors_output)
        statuses = {row["status"]: row["requests"] for row in rows}

        self.assertEqual(ingest_code, 0)
        self.assertIn("parsed=9 failed=1 skipped=0", ingest_output)
        self.assertEqual(export_code, 0)
        self.assertEqual(parse_errors_code, 0)
        self.assertEqual(len(parse_error_rows), 1)
        self.assertEqual(parse_error_rows[0]["log_type"], "access")
        self.assertEqual(statuses[200], 4)
        self.assertEqual(statuses[401], 2)

    def test_search_access_and_sql_rows_from_cli(self):
        access_sample = Path(__file__).resolve().parents[1] / "samples" / "nginx-access.log"
        sql_sample = Path(__file__).resolve().parents[1] / "samples" / "sql-execution.log"
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "search.db"

            self._run_cli(["ingest", str(access_sample), "--db", str(db_path)])
            self._run_cli(["ingest-sql", str(sql_sample), "--db", str(db_path)])

            access_code, access_output = self._run_cli(
                ["search-access", "--db", str(db_path), "--status", "401", "--format", "json"]
            )
            sql_code, sql_output = self._run_cli(
                [
                    "search-sql",
                    "--db",
                    str(db_path),
                    "--statement-type",
                    "SELECT",
                    "--min-duration-ms",
                    "100",
                    "--format",
                    "json",
                ]
            )

        access_rows = json.loads(access_output)
        sql_rows = json.loads(sql_output)

        self.assertEqual(access_code, 0)
        self.assertEqual(len(access_rows), 2)
        self.assertTrue(all(row["status"] == 401 for row in access_rows))
        self.assertEqual(sql_code, 0)
        self.assertEqual(len(sql_rows), 2)
        self.assertTrue(all(row["statement_type"] == "SELECT" for row in sql_rows))
        self.assertTrue(all(row["duration_ms"] >= 100 for row in sql_rows))

    def test_init_uses_global_db(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "custom.db"

            code, output = self._run_cli(["--db", str(db_path), "init"])

            conn = sqlite3.connect(db_path)
            try:
                table_count = conn.execute(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'access_logs'"
                ).fetchone()[0]
            finally:
                conn.close()

        self.assertEqual(code, 0)
        self.assertIn(f"initialized {db_path}", output)
        self.assertEqual(table_count, 1)

    def _run_cli(self, argv: list[str]) -> tuple[int, str]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(argv)
        return code, output.getvalue()


if __name__ == "__main__":
    unittest.main()
