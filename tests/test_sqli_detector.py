"""Unit tests for SQLInjectionDetector.

Verifies deterministic detection of SQL injection patterns (Boolean tautologies,
UNION SELECT, stacked queries, comment truncations, time-based blind queries)
as well as absence of false positives on benign web traffic.
"""

from datetime import datetime, timezone
import unittest

from soc_analyst.detection.sqli import SQLInjectionDetector
from soc_analyst.models.finding import Confidence, Severity
from soc_analyst.models.log_event import LogEvent


class TestSQLInjectionDetector(unittest.TestCase):
    """Test suite for validating SQL Injection detection rules and false-positive resistance."""

    def setUp(self) -> None:
        """Instantiate detector before each test."""
        self.detector = SQLInjectionDetector()

    def _make_event(
        self,
        path: str,
        source_ip: str = "192.168.1.100",
        timestamp: datetime | None = None,
    ) -> LogEvent:
        """Helper to create minimal LogEvent with specified path."""
        ts = timestamp or datetime(2026, 10, 10, 14, 0, 0, tzinfo=timezone.utc)
        return LogEvent(
            raw_line=f'{source_ip} - - [10/Oct/2026:14:00:00 +0000] "GET {path} HTTP/1.1" 200 1234',
            source_ip=source_ip,
            method="GET",
            path=path,
            status_code=200,
            timestamp=ts,
        )

    # -------------------------------------------------------------------------
    # 1. Malicious Payloads (True Positive Tests)
    # -------------------------------------------------------------------------

    def test_detect_boolean_tautology_quoted(self) -> None:
        """Detect classic quoted Boolean tautology (e.g., ' OR '1'='1)."""
        event = self._make_event("/products.php?id=1' OR '1'='1")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "SEC-SQLI-001")
        self.assertEqual(finding.attack_type, "SQL_INJECTION")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertIn("SQLI_BOOLEAN_TAUTOLOGY", finding.evidence)
        self.assertIn("OR '1'='1", finding.evidence)
        self.assertEqual(finding.source_ip, "192.168.1.100")
        self.assertIsNotNone(finding.technical_impact)
        self.assertIsNotNone(finding.business_impact)

    def test_detect_boolean_tautology_numeric(self) -> None:
        """Detect numeric Boolean tautology (e.g., OR 1=1)."""
        event = self._make_event("/search?category=books OR 1=1")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].attack_type, "SQL_INJECTION")
        self.assertIn("OR 1=1", findings[0].evidence)

    def test_detect_union_select(self) -> None:
        """Detect UNION-based query extraction attack."""
        event = self._make_event(
            "/catalog?cat=5 UNION SELECT null,username,password FROM users--"
        )
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "SEC-SQLI-001")
        self.assertIn("SQLI_UNION_SELECT", finding.evidence)
        self.assertIn("UNION SELECT", finding.evidence)

    def test_detect_union_all_select_case_insensitive(self) -> None:
        """Verify case-insensitive matching on 'uNiOn aLl sElEcT'."""
        event = self._make_event("/items?id=1 uNiOn aLl sElEcT 1,2,3")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("SQLI_UNION_SELECT", findings[0].evidence)

    def test_detect_stacked_queries_drop_table(self) -> None:
        """Detect stacked query executing DROP TABLE."""
        event = self._make_event("/api/records?id=10; DROP TABLE logs--")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("SQLI_STACKED_QUERIES", findings[0].evidence)
        self.assertIn("DROP TABLE", findings[0].evidence)

    def test_detect_comment_injection(self) -> None:
        """Detect SQL comment injection truncating backend query."""
        event = self._make_event("/login?user=admin'--")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("SQLI_COMMENT_INJECTION", findings[0].evidence)

    def test_detect_time_based_blind_sleep(self) -> None:
        """Detect time-based blind SQL injection probe (SLEEP function)."""
        event = self._make_event("/orders?filter=1' AND SLEEP(5)--")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("SQLI_TIME_BASED_BLIND", findings[0].evidence)
        self.assertIn("SLEEP(5)", findings[0].evidence)

    def test_detect_time_based_blind_waitfor(self) -> None:
        """Detect MS SQL Server WAITFOR DELAY injection."""
        event = self._make_event("/orders?id=1; WAITFOR DELAY '0:0:5'")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("SQLI_TIME_BASED_BLIND", findings[0].evidence)

    def test_detect_url_encoded_payload(self) -> None:
        """Ensure URL-encoded attack payloads are decoded and flagged correctly."""
        # "%27%20OR%20%271%27=%271" is URL-encoded "' OR '1'='1"
        event = self._make_event("/users?query=%27%20OR%20%271%27=%271")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("SQLI_BOOLEAN_TAUTOLOGY", findings[0].evidence)

    # -------------------------------------------------------------------------
    # 2. Benign Requests (Negative / False Positive Tests)
    # -------------------------------------------------------------------------

    def test_benign_product_sort(self) -> None:
        """Ensure normal sorting queries do not trigger false alarms."""
        event = self._make_event("/products?category=books&sort=price_asc")
        findings = self.detector.detect(event)
        self.assertEqual(findings, [])

    def test_benign_text_containing_and_or_words(self) -> None:
        """Ensure legitimate search phrases with 'and' or 'or' do not trigger false positives."""
        event1 = self._make_event("/search?q=rock+and+roll")
        event2 = self._make_event("/search?q=apples+or+oranges")
        self.assertEqual(self.detector.detect(event1), [])
        self.assertEqual(self.detector.detect(event2), [])

    def test_benign_text_containing_union(self) -> None:
        """Ensure benign URLs containing the word 'union' do not trigger false alarms."""
        event = self._make_event("/about/join-the-union")
        self.assertEqual(self.detector.detect(event), [])

    def test_benign_static_assets(self) -> None:
        """Ensure static asset requests produce zero findings."""
        event = self._make_event("/static/js/bundle.min.js")
        self.assertEqual(self.detector.detect(event), [])

    def test_benign_rest_api_call(self) -> None:
        """Ensure standard REST API queries do not trigger findings."""
        event = self._make_event("/api/v1/organizations/42/members?limit=25")
        self.assertEqual(self.detector.detect(event), [])

    # -------------------------------------------------------------------------
    # 3. Edge Cases & Batch Operations
    # -------------------------------------------------------------------------

    def test_detect_empty_path(self) -> None:
        """Verify empty or None path handles gracefully without errors."""
        event = LogEvent(raw_line="", path=None)
        findings = self.detector.detect(event)
        self.assertEqual(findings, [])

    def test_detect_all_aggregates_findings(self) -> None:
        """Verify detect_all aggregates findings across a stream of mixed events."""
        events = [
            self._make_event("/home"),
            self._make_event("/item?id=1' OR '1'='1"),
            self._make_event("/contact"),
            self._make_event("/data?q=1; DROP TABLE users"),
        ]

        findings = self.detector.detect_all(events)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].attack_type, "SQL_INJECTION")
        self.assertEqual(findings[1].attack_type, "SQL_INJECTION")


if __name__ == "__main__":
    unittest.main()
