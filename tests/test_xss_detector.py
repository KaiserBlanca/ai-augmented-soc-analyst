"""Unit tests for XSSDetector.

Verifies deterministic detection of Cross-Site Scripting (XSS) patterns (script tags,
pseudo-protocols, event handler injections, iframe injections, popup functions)
and guarantees absence of false alarms on benign traffic.
"""

from datetime import datetime, timezone
import unittest

from soc_analyst.detection.xss import XSSDetector
from soc_analyst.models.finding import Confidence, Severity
from soc_analyst.models.log_event import LogEvent


class TestXSSDetector(unittest.TestCase):
    """Test suite for validating XSS detection rules and false-positive resistance."""

    def setUp(self) -> None:
        """Instantiate detector before each test."""
        self.detector = XSSDetector()

    def _make_event(
        self,
        path: str,
        source_ip: str = "203.0.113.55",
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

    def test_detect_script_tag(self) -> None:
        """Detect classic <script> tag injection."""
        event = self._make_event("/search?q=<script>alert('XSS')</script>")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.rule_id, "SEC-XSS-001")
        self.assertEqual(finding.attack_type, "XSS")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.confidence, Confidence.HIGH)
        self.assertIn("XSS_SCRIPT_TAG", finding.evidence)
        self.assertIn("<script>", finding.evidence)
        self.assertEqual(finding.source_ip, "203.0.113.55")
        self.assertIsNotNone(finding.technical_impact)
        self.assertIsNotNone(finding.business_impact)

    def test_detect_script_tag_with_src(self) -> None:
        """Detect external script source tag injection."""
        event = self._make_event('/page?ref=<script src="http://evil.com/payload.js">')
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("XSS_SCRIPT_TAG", findings[0].evidence)

    def test_detect_event_handler_img_onerror(self) -> None:
        """Detect inline event handler on <img> tag."""
        event = self._make_event("/profile?name=<img src=x onerror=alert(1)>")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("XSS_EVENT_HANDLER_TAG", findings[0].evidence)

    def test_detect_event_handler_svg_onload(self) -> None:
        """Detect SVG element with automated onload execution."""
        event = self._make_event("/avatar?url=<svg onload=confirm('PWNED')>")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("XSS_EVENT_HANDLER_TAG", findings[0].evidence)

    def test_detect_javascript_pseudo_protocol(self) -> None:
        """Detect javascript: pseudo-protocol in link or redirection target."""
        event = self._make_event(
            "/redirect?next=javascript:alert(document.cookie)"
        )
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("XSS_PSEUDO_PROTOCOL", findings[0].evidence)

    def test_detect_iframe_tag_injection(self) -> None:
        """Detect <iframe> injection attempt."""
        event = self._make_event(
            "/comments?msg=<iframe src='http://attacker.com/steal.html'>"
        )
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("XSS_DANGEROUS_TAG", findings[0].evidence)

    def test_detect_url_encoded_xss(self) -> None:
        """Ensure URL-encoded XSS payloads are decoded and detected accurately."""
        # "%3Cscript%3Ealert(1)%3C%2Fscript%3E" is URL-encoded "<script>alert(1)</script>"
        event = self._make_event("/feedback?text=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("XSS_SCRIPT_TAG", findings[0].evidence)

    def test_detect_popup_function_call(self) -> None:
        """Detect direct function call to alert() with document.cookie argument."""
        event = self._make_event("/test?cb=alert(document.cookie)")
        findings = self.detector.detect(event)

        self.assertEqual(len(findings), 1)
        self.assertIn("XSS_POPUP_OR_COOKIE_FUNCTION", findings[0].evidence)

    # -------------------------------------------------------------------------
    # 2. Benign Requests (Negative / False Positive Tests)
    # -------------------------------------------------------------------------

    def test_benign_search_for_javascript(self) -> None:
        """Ensure searching for programming language terms like 'javascript' does not alert."""
        event = self._make_event("/blog/search?q=javascript+async+await+tutorial")
        findings = self.detector.detect(event)
        self.assertEqual(findings, [])

    def test_benign_html_page_request(self) -> None:
        """Ensure standard requests for static HTML files produce no findings."""
        event = self._make_event("/docs/api-guide.html")
        findings = self.detector.detect(event)
        self.assertEqual(findings, [])

    def test_benign_user_profile_query(self) -> None:
        """Ensure routine user profile URL query parameters do not trigger findings."""
        event = self._make_event(
            "/users/profile?id=9482&username=john_doe&view=summary"
        )
        findings = self.detector.detect(event)
        self.assertEqual(findings, [])

    def test_benign_redirect_parameter(self) -> None:
        """Ensure safe relative or HTTP URL redirects do not match pseudo-protocols."""
        event = self._make_event("/login?return_to=https://example.com/dashboard")
        findings = self.detector.detect(event)
        self.assertEqual(findings, [])

    # -------------------------------------------------------------------------
    # 3. Edge Cases & Batch Operations
    # -------------------------------------------------------------------------

    def test_detect_empty_path(self) -> None:
        """Verify empty or None path handles gracefully without errors."""
        event = LogEvent(raw_line="", path=None)
        findings = self.detector.detect(event)
        self.assertEqual(findings, [])

    def test_detect_all_aggregates_findings(self) -> None:
        """Verify detect_all aggregates findings across a collection of events."""
        events = [
            self._make_event("/index.html"),
            self._make_event("/search?q=<script>alert(1)</script>"),
            self._make_event("/about"),
            self._make_event("/profile?name=<img src=x onerror=alert(2)>"),
        ]

        findings = self.detector.detect_all(events)
        self.assertEqual(len(findings), 2)
        self.assertEqual(findings[0].attack_type, "XSS")
        self.assertEqual(findings[1].attack_type, "XSS")


if __name__ == "__main__":
    unittest.main()
