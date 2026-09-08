"""Unit tests for LogEvent and Finding models."""

from dataclasses import FrozenInstanceError
from datetime import datetime
import unittest

from soc_analyst.models import Confidence, Finding, LogEvent, Severity


class TestModels(unittest.TestCase):
    """Test suite verifying immutability, validation, and structures of models."""

    def test_log_event_frozen(self) -> None:
        """Ensure LogEvent is immutable and cannot be modified after instantiation."""
        event = LogEvent(
            raw_line='127.0.0.1 - - [09/Sep/2026:01:00:00 +0000] "GET / HTTP/1.1" 200 1234',
            source_ip="127.0.0.1",
            method="GET",
            path="/",
            status_code=200,
        )
        self.assertEqual(event.source_ip, "127.0.0.1")
        self.assertEqual(event.method, "GET")

        with self.assertRaises(FrozenInstanceError):
            setattr(event, "source_ip", "10.0.0.1")

    def test_finding_creation_and_attributes(self) -> None:
        """Ensure Finding model properly initializes with Severity and Confidence enums."""
        now = datetime.now()
        finding = Finding(
            rule_id="SEC-SQLI-001",
            attack_type="SQL_INJECTION",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Potential SQL injection detected in query parameter",
            evidence="id=1' OR '1'='1",
            technical_impact="Unauthorized database manipulation or exfiltration",
            business_impact="Customer data exposure and compliance penalties",
            source_ip="192.168.1.100",
            timestamp=now,
            recommended_action="Employ prepared statements and input validation",
            ai_enrichment=None,
        )

        self.assertEqual(finding.rule_id, "SEC-SQLI-001")
        self.assertEqual(finding.attack_type, "SQL_INJECTION")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.confidence, Confidence.MEDIUM)
        self.assertEqual(finding.source_ip, "192.168.1.100")
        self.assertEqual(finding.timestamp, now)
        self.assertIsNone(finding.ai_enrichment)

    def test_finding_frozen(self) -> None:
        """Ensure Finding instance is immutable."""
        finding = Finding(
            rule_id="SEC-XSS-001",
            attack_type="XSS",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="Reflected XSS payload in parameter",
            evidence="<script>alert(1)</script>",
            technical_impact="Client-side script execution in victim browser context",
            business_impact="Session hijacking and credential theft",
        )

        with self.assertRaises(FrozenInstanceError):
            setattr(finding, "severity", Severity.CRITICAL)

    def test_severity_confidence_values(self) -> None:
        """Verify expected enum values for Severity and Confidence."""
        self.assertEqual(Severity.LOW.value, "LOW")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")

        self.assertEqual(Confidence.LOW.value, "LOW")
        self.assertEqual(Confidence.MEDIUM.value, "MEDIUM")
        self.assertEqual(Confidence.HIGH.value, "HIGH")


if __name__ == "__main__":
    unittest.main()
