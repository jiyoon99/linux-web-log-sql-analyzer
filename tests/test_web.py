import unittest

from linux_web_log_sql_analyzer.web import _optional_float, _optional_int, _render_dashboard


class WebRenderTest(unittest.TestCase):
    def test_dashboard_has_tabs_filters_and_escaped_values(self):
        html = _render_dashboard(
            {"total": 1, "parse_errors": 0, "client_errors": 0, "server_errors": 0, "unique_ips": 1, "unique_paths": 1},
            {"total": 1, "parse_errors": 0, "avg_duration_ms": 15, "max_duration_ms": 15, "unique_tables": 1, "statement_types": 1},
            {
                "Status": [{"status": 200, "requests": 1}],
                "Hourly Traffic": [{"hour": "2026-06-04T00:00:00Z", "requests": 1}],
                "Top Paths": [{"path": "<script>alert(1)</script>", "requests": 1, "errors": 0}],
                "Suspicious IPs": [],
                "Access Search Results": [{"path": "/login", "status": 401}],
                "Slow SQL": [{"statement": "SELECT * FROM members", "duration_ms": 15}],
                "SQL Types": [{"statement_type": "SELECT", "queries": 1}],
                "SQL Tables": [{"table_name": "members", "queries": 1}],
                "SQL Search Results": [{"statement": "SELECT * FROM members", "duration_ms": 15}],
                "Parse Errors": [{"source": "samples/nginx-access.log", "line_no": 10, "log_type": "access", "parse_error": "unsupported access log format", "raw_text": "bad line"}],
            },
        )

        self.assertIn("data-tab=\"access\"", html)
        self.assertIn("data-tab=\"parse\"", html)
        self.assertIn("action=\"/\"", html)
        self.assertIn("name=\"tab\" value=\"access\"", html)
        self.assertIn("name=\"tab\" value=\"sql\"", html)
        self.assertIn("Parse Errors", html)
        self.assertIn("Access Search Results", html)
        self.assertIn("SQL Search Results", html)
        self.assertIn("Status Distribution", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_blank_query_values_are_ignored(self):
        self.assertIsNone(_optional_int(""))
        self.assertEqual(_optional_int("", 50), 50)
        self.assertEqual(_optional_int("20"), 20)
        self.assertIsNone(_optional_float(""))
        self.assertEqual(_optional_float("12.5"), 12.5)

    def test_invalid_numeric_values_raise(self):
        with self.assertRaises(Exception):
            _optional_int("abc", name="status")
        with self.assertRaises(Exception):
            _optional_float("abc", name="min_duration_ms")


if __name__ == "__main__":
    unittest.main()
