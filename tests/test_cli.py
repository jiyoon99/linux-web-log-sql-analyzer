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

        rows = json.loads(export_output)
        statuses = {row["status"]: row["requests"] for row in rows}

        self.assertEqual(ingest_code, 0)
        self.assertIn("parsed=9 failed=1 skipped=0", ingest_output)
        self.assertEqual(export_code, 0)
        self.assertEqual(statuses[200], 4)
        self.assertEqual(statuses[401], 2)

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
