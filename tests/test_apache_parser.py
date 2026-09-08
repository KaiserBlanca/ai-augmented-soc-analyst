"""Unit tests for the Apache HTTP Server log parser.

Verifies correct parsing of both Apache Common Log Format (CLF) and Combined Log Format,
as well as defensive error handling and graceful degradation on malformed or corrupted log entries.
"""

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from soc_analyst.models.log_event import LogEvent
from soc_analyst.parsers.apache import (
    ApacheLogParser,
    parse_file,
    parse_line,
    parse_lines,
)


class TestApacheParser(unittest.TestCase):
    """Test suite verifying parsing correctness and graceful degradation of the Apache parser."""

    def setUp(self) -> None:
        """Set up a fresh parser instance before each test."""
        self.parser = ApacheLogParser()

    # -------------------------------------------------------------------------
    # 1. Combined Log Format Tests (Valid Lines)
    # -------------------------------------------------------------------------

    def test_parse_valid_combined_log_standard(self) -> None:
        """Test parsing of a standard Apache Combined log line with all fields present."""
        raw_line = (
            '192.168.1.100 - frank [10/Oct/2026:13:55:36 -0700] '
            '"GET /index.html HTTP/1.1" 200 2326 '
            '"http://example.com/start.html" '
            '"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None  # For type-checker narrowing
        self.assertEqual(event.raw_line, raw_line)
        self.assertEqual(event.source_ip, "192.168.1.100")
        self.assertEqual(event.user, "frank")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/index.html")
        self.assertEqual(event.status_code, 200)
        self.assertEqual(
            event.user_agent, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        )
        self.assertIsNotNone(event.timestamp)
        assert event.timestamp is not None
        self.assertEqual(event.timestamp.year, 2026)
        self.assertEqual(event.timestamp.month, 10)
        self.assertEqual(event.timestamp.day, 10)
        self.assertEqual(event.timestamp.hour, 13)
        self.assertEqual(event.timestamp.minute, 55)
        self.assertEqual(event.timestamp.second, 36)

    def test_parse_valid_combined_log_anonymous_user_and_hyphen_headers(
        self,
    ) -> None:
        """Test parsing when remote user, referer, and user agent are hyphens ('-')."""
        raw_line = (
            '10.0.0.1 - - [09/Sep/2026:01:00:00 +0000] '
            '"POST /api/v1/telemetry HTTP/2.0" 204 0 "-" "-"'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source_ip, "10.0.0.1")
        self.assertIsNone(event.user)
        self.assertEqual(event.method, "POST")
        self.assertEqual(event.path, "/api/v1/telemetry")
        self.assertEqual(event.status_code, 204)
        self.assertIsNone(event.user_agent)
        self.assertEqual(
            event.timestamp, datetime(2026, 9, 9, 1, 0, 0, tzinfo=timezone.utc)
        )

    def test_parse_valid_combined_ipv6(self) -> None:
        """Ensure IPv6 client addresses are parsed correctly."""
        raw_line = (
            '2001:0db8:85a3:0000:0000:8a2e:0370:7334 - - '
            '[10/Oct/2026:14:00:00 +0000] "GET /status HTTP/1.1" 200 45 "-" "curl/7.68.0"'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(
            event.source_ip, "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        )
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/status")
        self.assertEqual(event.user_agent, "curl/7.68.0")

    # -------------------------------------------------------------------------
    # 2. Common Log Format (CLF) Tests (Valid Lines)
    # -------------------------------------------------------------------------

    def test_parse_valid_common_log_standard(self) -> None:
        """Test parsing of a standard Apache Common Log Format (CLF) line."""
        raw_line = (
            '127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] '
            '"GET /apache_pb.gif HTTP/1.0" 200 2326'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.raw_line, raw_line)
        self.assertEqual(event.source_ip, "127.0.0.1")
        self.assertEqual(event.user, "frank")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/apache_pb.gif")
        self.assertEqual(event.status_code, 200)
        # Common format does not provide User-Agent
        self.assertIsNone(event.user_agent)

    def test_parse_valid_common_log_with_hyphens(self) -> None:
        """Test Common log format with missing auth user and empty response bytes ('-')."""
        raw_line = (
            '172.16.1.20 - - [10/Oct/2026:13:55:36 +0000] '
            '"HEAD /check HTTP/1.1" 304 -'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source_ip, "172.16.1.20")
        self.assertIsNone(event.user)
        self.assertEqual(event.method, "HEAD")
        self.assertEqual(event.path, "/check")
        self.assertEqual(event.status_code, 304)
        self.assertIsNone(event.user_agent)

    # -------------------------------------------------------------------------
    # 3. Security Payload & Special Character Tests
    # -------------------------------------------------------------------------

    def test_parse_security_payload_sqli(self) -> None:
        """Ensure SQL injection payloads in request query strings are accurately parsed."""
        raw_line = (
            '198.51.100.42 - - [10/Oct/2026:14:10:00 +0000] '
            '"GET /item.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 8920 "-" "sqlmap/1.5#stable"'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source_ip, "198.51.100.42")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/item.php?id=1' OR '1'='1")
        self.assertEqual(event.user_agent, "sqlmap/1.5#stable")

    def test_parse_security_payload_xss(self) -> None:
        """Ensure XSS attack payloads in request paths are preserved for downstream detection."""
        raw_line = (
            '203.0.113.15 - - [10/Oct/2026:14:12:30 +0000] '
            '"GET /search?q=<script>alert(\'XSS\')</script> HTTP/1.1" 403 342 "-" "Mozilla/5.0"'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source_ip, "203.0.113.15")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/search?q=<script>alert('XSS')</script>")
        self.assertEqual(event.status_code, 403)

    def test_parse_security_payload_directory_traversal(self) -> None:
        """Ensure directory traversal payloads are properly extracted."""
        raw_line = (
            '192.0.2.1 - - [10/Oct/2026:14:15:00 +0000] '
            '"GET /../../../../etc/passwd HTTP/1.1" 400 0 "-" "Nikto/2.1.6"'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source_ip, "192.0.2.1")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/../../../../etc/passwd")
        self.assertEqual(event.status_code, 400)
        self.assertEqual(event.user_agent, "Nikto/2.1.6")

    # -------------------------------------------------------------------------
    # 4. Graceful Degradation & Corrupted Log Line Handling
    # -------------------------------------------------------------------------

    def test_parse_empty_and_whitespace_lines(self) -> None:
        """Verify that empty and whitespace lines return None without crashing."""
        self.assertIsNone(self.parser.parse_line(""))
        self.assertIsNone(self.parser.parse_line("   "))
        self.assertIsNone(self.parser.parse_line("\n"))
        self.assertIsNone(self.parser.parse_line("   \r\n"))

    def test_parse_completely_corrupted_line(self) -> None:
        """Verify that completely unparseable random strings return None without raising errors."""
        corrupted = "Corrupted non-log data with arbitrary garbage !!!"
        self.assertIsNone(self.parser.parse_line(corrupted))

    def test_parse_truncated_lines(self) -> None:
        """Verify that incomplete or truncated log lines return None gracefully."""
        # Missing status, bytes, and request
        truncated_1 = "192.168.1.1 - -"
        # Missing quotes around request
        truncated_2 = (
            "192.168.1.1 - - [10/Oct/2026:14:00:00 +0000] GET /index.html 200"
        )
        # Missing trailing quotes
        truncated_3 = (
            '192.168.1.1 - - [10/Oct/2026:14:00:00 +0000] "GET /index.html'
        )

        self.assertIsNone(self.parser.parse_line(truncated_1))
        self.assertIsNone(self.parser.parse_line(truncated_2))
        self.assertIsNone(self.parser.parse_line(truncated_3))

    def test_parse_malformed_timestamp_degrades_gracefully(self) -> None:
        """Ensure a line with an invalid timestamp still extracts other valid fields."""
        raw_line = (
            '192.168.1.50 - bob [not-a-valid-date-string] '
            '"GET /dashboard HTTP/1.1" 200 1024'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        # Timestamp must degrade to None
        self.assertIsNone(event.timestamp)
        # Other fields should still be intact for SOC inspection
        self.assertEqual(event.source_ip, "192.168.1.50")
        self.assertEqual(event.user, "bob")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/dashboard")
        self.assertEqual(event.status_code, 200)

    def test_parse_malformed_status_code_degrades_gracefully(self) -> None:
        """Ensure a line with a non-numeric status code '-' produces status_code=None."""
        raw_line = (
            '10.10.10.10 - - [10/Oct/2026:14:00:00 +0000] '
            '"GET /hung-connection HTTP/1.1" - -'
        )

        event = self.parser.parse_line(raw_line)

        self.assertIsNotNone(event)
        assert event is not None
        self.assertIsNone(event.status_code)
        self.assertEqual(event.source_ip, "10.10.10.10")
        self.assertEqual(event.method, "GET")
        self.assertEqual(event.path, "/hung-connection")

    def test_parse_unusual_request_formats(self) -> None:
        """Verify handling of abnormal HTTP request formats (e.g. empty or single token)."""
        # Request is just '-'
        raw_line_empty_req = (
            '1.2.3.4 - - [10/Oct/2026:14:00:00 +0000] "-" 400 0'
        )
        event1 = self.parser.parse_line(raw_line_empty_req)
        self.assertIsNotNone(event1)
        assert event1 is not None
        self.assertIsNone(event1.method)
        self.assertIsNone(event1.path)
        self.assertEqual(event1.status_code, 400)

        # Request is a single token
        raw_line_single_token = (
            '1.2.3.4 - - [10/Oct/2026:14:00:00 +0000] "OPTIONS" 200 0'
        )
        event2 = self.parser.parse_line(raw_line_single_token)
        self.assertIsNotNone(event2)
        assert event2 is not None
        self.assertEqual(event2.method, "OPTIONS")
        self.assertIsNone(event2.path)

    # -------------------------------------------------------------------------
    # 5. Batch & File Processing Tests
    # -------------------------------------------------------------------------

    def test_parse_lines_mixed_valid_and_corrupt(self) -> None:
        """Test parsing multiple lines with mixed valid and corrupted entries."""
        lines = [
            '192.168.1.1 - - [10/Oct/2026:14:00:00 +0000] "GET /home HTTP/1.1" 200 500',
            "",
            "completely corrupted line that must be skipped",
            '192.168.1.2 - - [10/Oct/2026:14:00:01 +0000] "POST /login HTTP/1.1" 401 200',
            "   \n",
            '192.168.1.3 - admin [10/Oct/2026:14:00:02 +0000] "GET /admin HTTP/1.1" 200 1000 "-" "curl"',
        ]

        events = self.parser.parse_lines(lines)

        self.assertEqual(len(events), 3)
        self.assertEqual(events[0].source_ip, "192.168.1.1")
        self.assertEqual(events[0].path, "/home")
        self.assertEqual(events[1].source_ip, "192.168.1.2")
        self.assertEqual(events[1].status_code, 401)
        self.assertEqual(events[2].source_ip, "192.168.1.3")
        self.assertEqual(events[2].user, "admin")

    def test_parse_file_success(self) -> None:
        """Test reading and parsing an Apache log file from disk."""
        log_content = (
            '10.0.0.1 - - [10/Oct/2026:12:00:00 +0000] "GET /file1 HTTP/1.1" 200 1234\n'
            'corrupted line\n'
            '10.0.0.2 - - [10/Oct/2026:12:00:01 +0000] "GET /file2 HTTP/1.1" 404 321 "-" "pytest"\n'
        )

        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        ) as tmp:
            tmp.write(log_content)
            tmp_path = Path(tmp.name)

        try:
            events = parse_file(tmp_path)
            self.assertEqual(len(events), 2)
            self.assertEqual(events[0].path, "/file1")
            self.assertEqual(events[1].path, "/file2")
            self.assertEqual(events[1].user_agent, "pytest")
        finally:
            tmp_path.unlink(missing_ok=True)

    def test_parse_file_non_existent(self) -> None:
        """Verify parse_file handles non-existent file path gracefully by returning empty list."""
        non_existent = Path("non_existent_apache_access.log")
        events = parse_file(non_existent)
        self.assertEqual(events, [])

    def test_module_level_convenience_functions(self) -> None:
        """Ensure module-level parse_line and parse_lines behave identically to parser instance."""
        line = (
            '1.1.1.1 - - [10/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100'
        )
        event = parse_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.source_ip, "1.1.1.1")

        events = parse_lines([line, "invalid"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].source_ip, "1.1.1.1")


if __name__ == "__main__":
    unittest.main()
