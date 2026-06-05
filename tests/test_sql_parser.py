from pathlib import Path
import unittest

from linux_web_log_sql_analyzer.sql_parser import parse_simple_sql_line, parse_sql_log_file


class SqlParserTest(unittest.TestCase):
    def test_simple_execution_line(self):
        parsed = parse_simple_sql_line(
            "[2026-06-04 00:00:03] 18ms SELECT id, email FROM members WHERE email = 'user@example.test'",
            source="sample",
            line_no=1,
        )

        self.assertIsNone(parsed.parse_error)
        self.assertEqual(parsed.statement_type, "SELECT")
        self.assertEqual(parsed.table_name, "members")
        self.assertEqual(parsed.duration_ms, 18)

    def test_sensitive_sql_values_are_masked(self):
        parsed = parse_simple_sql_line(
            "[2026-06-04 00:00:03] 18ms UPDATE users SET password = 'secret', api_key = 'abc' WHERE session_id = 'sid'",
            source="sample",
            line_no=2,
        )

        self.assertIsNone(parsed.parse_error)
        self.assertIn("password = '***'", parsed.statement)
        self.assertIn("api_key = '***'", parsed.statement)
        self.assertIn("session_id = '***'", parsed.statement)
        self.assertNotIn("secret", parsed.statement)
        self.assertNotIn("abc", parsed.raw_entry)
        self.assertNotIn("sid", parsed.raw_entry)

    def test_insert_sensitive_positional_values_are_masked(self):
        parsed = parse_simple_sql_line(
            "[2026-06-04 00:00:04] 21ms INSERT INTO users (email, password, api_key, session_id, display_name) "
            "VALUES ('user@example.test', 'secret-password', 'api-secret', 'session-secret', 'Jiyoon')",
            source="sample",
            line_no=3,
        )

        self.assertIsNone(parsed.parse_error)
        self.assertEqual(parsed.statement_type, "INSERT")
        self.assertIn("VALUES ('user@example.test', '***', '***', '***', 'Jiyoon')", parsed.statement)
        self.assertIn("VALUES ('user@example.test', '***', '***', '***', 'Jiyoon')", parsed.raw_entry)
        self.assertNotIn("secret-password", parsed.statement)
        self.assertNotIn("api-secret", parsed.statement)
        self.assertNotIn("session-secret", parsed.statement)
        self.assertNotIn("secret-password", parsed.raw_entry)
        self.assertNotIn("api-secret", parsed.raw_entry)
        self.assertNotIn("session-secret", parsed.raw_entry)

    def test_mysql_slow_log_file(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "mysql-slow.log"
        parsed = parse_sql_log_file(sample)

        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].statement_type, "SELECT")
        self.assertEqual(parsed[0].table_name, "members")
        self.assertEqual(parsed[0].duration_ms, 1250)
        self.assertEqual(parsed[1].statement_type, "DELETE")
        self.assertEqual(parsed[1].table_name, "sessions")


if __name__ == "__main__":
    unittest.main()
