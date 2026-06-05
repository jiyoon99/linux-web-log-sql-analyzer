import unittest

from linux_web_log_sql_analyzer.parser import parse_access_log_line


class ParserTest(unittest.TestCase):
    def test_combined_nginx_line(self):
        line = '203.0.113.10 - - [04/Jun/2026:09:00:01 +0900] "GET /products?q=coffee HTTP/1.1" 200 1240 "-" "Mozilla/5.0"'
        parsed = parse_access_log_line(line, source="sample", line_no=1)

        self.assertIsNone(parsed.parse_error)
        self.assertEqual(parsed.remote_addr, "203.0.113.10")
        self.assertEqual(parsed.method, "GET")
        self.assertEqual(parsed.path, "/products")
        self.assertEqual(parsed.query, "q=coffee")
        self.assertEqual(parsed.status, 200)
        self.assertEqual(parsed.bytes_sent, 1240)

    def test_bad_line_is_preserved(self):
        parsed = parse_access_log_line("not an access log", source="sample", line_no=2)

        self.assertIsNotNone(parsed.parse_error)
        self.assertEqual(parsed.raw_line, "not an access log")

    def test_sensitive_query_values_are_masked(self):
        line = '203.0.113.10 - - [04/Jun/2026:09:00:01 +0900] "GET /callback?token=abc123&ok=1 HTTP/1.1" 200 1240 "https://example.test/login?password=secret" "Mozilla/5.0"'
        parsed = parse_access_log_line(line, source="sample", line_no=3)

        self.assertEqual(parsed.query, "token=%2A%2A%2A&ok=1")
        self.assertEqual(parsed.referrer, "https://example.test/login?password=%2A%2A%2A")
        self.assertNotIn("abc123", parsed.raw_line)
        self.assertNotIn("secret", parsed.raw_line)

    def test_sensitive_query_key_variants_are_masked(self):
        line = '203.0.113.10 - - [04/Jun/2026:09:00:01 +0900] "GET /callback?session_id=abc123&apiKey=secret&access-token=tok&ok=1 HTTP/1.1" 200 1240 "-" "Mozilla/5.0"'
        parsed = parse_access_log_line(line, source="sample", line_no=4)

        self.assertIn("session_id=%2A%2A%2A", parsed.query)
        self.assertIn("apiKey=%2A%2A%2A", parsed.query)
        self.assertIn("access-token=%2A%2A%2A", parsed.query)
        self.assertIn("ok=1", parsed.query)
        self.assertNotIn("abc123", parsed.raw_line)
        self.assertNotIn("secret", parsed.raw_line)
        self.assertNotIn("access-token=tok", parsed.raw_line)

    def test_common_log_without_referrer_user_agent(self):
        line = '203.0.113.11 - - [04/Jun/2026:09:00:01 +0900] "GET /health HTTP/1.1" 204 -'
        parsed = parse_access_log_line(line, source="sample", line_no=5)

        self.assertIsNone(parsed.parse_error)
        self.assertEqual(parsed.path, "/health")
        self.assertEqual(parsed.status, 204)
        self.assertIsNone(parsed.bytes_sent)
        self.assertIsNone(parsed.referrer)
        self.assertIsNone(parsed.user_agent)
        self.assertEqual(parsed.requested_at, "2026-06-04T00:00:01+00:00")

    def test_dash_status_and_bytes_are_none(self):
        line = '203.0.113.12 - - [04/Jun/2026:09:00:01 +0000] "GET /pending HTTP/1.1" - - "-" "curl/8"'
        parsed = parse_access_log_line(line, source="sample", line_no=6)

        self.assertIsNone(parsed.parse_error)
        self.assertIsNone(parsed.status)
        self.assertIsNone(parsed.bytes_sent)

    def test_invalid_timestamp_keeps_parsed_log(self):
        line = '203.0.113.13 - - [not-a-date] "GET /weird HTTP/1.1" 200 1 "-" "curl/8"'
        parsed = parse_access_log_line(line, source="sample", line_no=7)

        self.assertIsNone(parsed.parse_error)
        self.assertEqual(parsed.path, "/weird")
        self.assertIsNone(parsed.requested_at)


if __name__ == "__main__":
    unittest.main()
