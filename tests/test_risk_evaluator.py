"""Unit tests for the RiskEvaluator module.

Verifies deterministic calculation of dynamic risk scores (0-100), evaluating the impact
of threat Severity, Confidence, and contextual HTTP status codes (e.g. 200 OK vs 403 vs 404).
"""

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
import unittest

from soc_analyst.models.finding import Confidence, Finding, Severity
from soc_analyst.models.log_event import LogEvent
from soc_analyst.risk.evaluator import (
    RiskAssessment,
    RiskEvaluator,
    calculate_risk_score,
    evaluate_risk,
)


class TestRiskEvaluator(unittest.TestCase):
    """Test suite for validating risk evaluation algorithms and status code sensitivities."""

    def setUp(self) -> None:
        """Instantiate a fresh evaluator before each test."""
        self.evaluator = RiskEvaluator()

    def _create_finding(
        self,
        severity: Severity = Severity.HIGH,
        confidence: Confidence = Confidence.HIGH,
        attack_type: str = "SQL_INJECTION",
    ) -> Finding:
        """Helper to create dummy Finding with specified severity and confidence."""
        return Finding(
            rule_id="SEC-TEST-001",
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            description="Test finding for risk evaluation",
            evidence="Matched payload fragment",
            technical_impact="Potential technical impact",
            business_impact="Potential business impact",
            source_ip="192.168.1.50",
            timestamp=datetime(2026, 10, 10, 14, 0, 0, tzinfo=timezone.utc),
        )

    def _create_log_event(self, status_code: int | None) -> LogEvent:
        """Helper to create minimal LogEvent with given status code."""
        return LogEvent(
            raw_line="raw log line",
            source_ip="192.168.1.50",
            method="GET",
            path="/target",
            status_code=status_code,
        )

    # -------------------------------------------------------------------------
    # 1. HTTP Status Code Sensitivity Tests
    # -------------------------------------------------------------------------

    def test_status_code_comparison_200_vs_403_vs_404(self) -> None:
        """Verify that an attack returning HTTP 200 is scored significantly higher than 403 and 404.

        Requirements:
            - HTTP 200 OK indicates execution/success: Highest modifier (+20)
            - HTTP 403 Forbidden indicates boundary block: Moderate modifier (+5)
            - HTTP 404 Not Found indicates missing endpoint: Zero modifier (0)
        """
        sqli_finding = self._create_finding(
            severity=Severity.HIGH, confidence=Confidence.HIGH
        )

        score_200 = self.evaluator.calculate_score(
            sqli_finding, self._create_log_event(200)
        )
        score_500 = self.evaluator.calculate_score(
            sqli_finding, self._create_log_event(500)
        )
        score_403 = self.evaluator.calculate_score(
            sqli_finding, self._create_log_event(403)
        )
        score_404 = self.evaluator.calculate_score(
            sqli_finding, self._create_log_event(404)
        )

        # Exact expected points:
        # High (40) + High (30) + 200 (20) = 90
        # High (40) + High (30) + 500 (15) = 85
        # High (40) + High (30) + 403 (5)  = 75
        # High (40) + High (30) + 404 (0)  = 70
        self.assertEqual(score_200, 90)
        self.assertEqual(score_500, 85)
        self.assertEqual(score_403, 75)
        self.assertEqual(score_404, 70)

        # Cardinal comparison: 200 > 500 > 403 > 404
        self.assertGreater(score_200, score_500)
        self.assertGreater(score_500, score_403)
        self.assertGreater(score_403, score_404)

    def test_xss_status_code_differentiation(self) -> None:
        """Verify status code differentiation on XSS (Severity: MEDIUM, Confidence: HIGH)."""
        xss_finding = self._create_finding(
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            attack_type="XSS",
        )

        # Medium (25) + High (30) + 200 (20) = 75
        score_200 = self.evaluator.calculate_score(
            xss_finding, self._create_log_event(200)
        )
        # Medium (25) + High (30) + 403 (5) = 60
        score_403 = self.evaluator.calculate_score(
            xss_finding, self._create_log_event(403)
        )
        # Medium (25) + High (30) + 404 (0) = 55
        score_404 = self.evaluator.calculate_score(
            xss_finding, self._create_log_event(404)
        )

        self.assertEqual(score_200, 75)
        self.assertEqual(score_403, 60)
        self.assertEqual(score_404, 55)
        self.assertGreater(score_200, score_403)
        self.assertGreater(score_403, score_404)

    def test_missing_or_unparseable_status_code(self) -> None:
        """Ensure missing status code uses neutral fallback (+5) without crashing."""
        finding = self._create_finding(
            severity=Severity.HIGH, confidence=Confidence.MEDIUM
        )
        # High (40) + Medium (20) + Neutral (5) = 65
        score_none = self.evaluator.calculate_score(
            finding, self._create_log_event(None)
        )
        score_no_event = self.evaluator.calculate_score(finding, log_event=None)

        self.assertEqual(score_none, 65)
        self.assertEqual(score_no_event, 65)

    # -------------------------------------------------------------------------
    # 2. Severity & Confidence Matrix Tests
    # -------------------------------------------------------------------------

    def test_severity_ordering(self) -> None:
        """Ensure risk score increases monotonically with higher Severity tiers."""
        conf = Confidence.HIGH
        st = 200

        score_crit = self.evaluator.calculate_score(
            self._create_finding(severity=Severity.CRITICAL, confidence=conf),
            status_code=st,
        )
        score_high = self.evaluator.calculate_score(
            self._create_finding(severity=Severity.HIGH, confidence=conf),
            status_code=st,
        )
        score_med = self.evaluator.calculate_score(
            self._create_finding(severity=Severity.MEDIUM, confidence=conf),
            status_code=st,
        )
        score_low = self.evaluator.calculate_score(
            self._create_finding(severity=Severity.LOW, confidence=conf),
            status_code=st,
        )

        # 50+30+20 = 100
        self.assertEqual(score_crit, 100)
        # 40+30+20 = 90
        self.assertEqual(score_high, 90)
        # 25+30+20 = 75
        self.assertEqual(score_med, 75)
        # 10+30+20 = 60
        self.assertEqual(score_low, 60)

        self.assertGreater(score_crit, score_high)
        self.assertGreater(score_high, score_med)
        self.assertGreater(score_med, score_low)

    def test_confidence_ordering(self) -> None:
        """Ensure risk score reflects confidence when severity is held constant."""
        sev = Severity.HIGH
        st = 200

        score_conf_high = self.evaluator.calculate_score(
            self._create_finding(severity=sev, confidence=Confidence.HIGH),
            status_code=st,
        )
        score_conf_med = self.evaluator.calculate_score(
            self._create_finding(severity=sev, confidence=Confidence.MEDIUM),
            status_code=st,
        )
        score_conf_low = self.evaluator.calculate_score(
            self._create_finding(severity=sev, confidence=Confidence.LOW),
            status_code=st,
        )

        # 40 + 30 + 20 = 90
        self.assertEqual(score_conf_high, 90)
        # 40 + 20 + 20 = 80
        self.assertEqual(score_conf_med, 80)
        # 40 + 10 + 20 = 70
        self.assertEqual(score_conf_low, 70)

        self.assertGreater(score_conf_high, score_conf_med)
        self.assertGreater(score_conf_med, score_conf_low)

    # -------------------------------------------------------------------------
    # 3. Boundary Clamping Tests
    # -------------------------------------------------------------------------

    def test_score_clamping_max_100(self) -> None:
        """Verify scores cannot exceed 100."""
        finding = self._create_finding(
            severity=Severity.CRITICAL, confidence=Confidence.HIGH
        )
        score = self.evaluator.calculate_score(finding, status_code=200)
        self.assertLessEqual(score, 100)
        self.assertEqual(score, 100)

    def test_score_clamping_min_0(self) -> None:
        """Verify lowest possible score remains non-negative."""
        finding = self._create_finding(
            severity=Severity.LOW, confidence=Confidence.LOW
        )
        score = self.evaluator.calculate_score(finding, status_code=404)
        self.assertGreaterEqual(score, 0)
        # 10 + 10 + 0 = 20
        self.assertEqual(score, 20)

    # -------------------------------------------------------------------------
    # 4. Structured RiskAssessment Model Tests
    # -------------------------------------------------------------------------

    def test_evaluate_produces_structured_assessment(self) -> None:
        """Verify detailed fields and immutability of RiskAssessment."""
        finding = self._create_finding(
            severity=Severity.HIGH, confidence=Confidence.HIGH
        )
        event = self._create_log_event(200)

        assessment = self.evaluator.evaluate(finding, log_event=event)

        self.assertIsInstance(assessment, RiskAssessment)
        self.assertEqual(assessment.finding, finding)
        self.assertEqual(assessment.risk_score, 90)
        self.assertEqual(assessment.risk_level, Severity.CRITICAL)
        self.assertEqual(assessment.status_code, 200)
        self.assertEqual(assessment.severity_points, 40)
        self.assertEqual(assessment.confidence_points, 30)
        self.assertEqual(assessment.status_code_modifier, 20)
        self.assertIn("90/100", assessment.rationale)

        # Immutability check
        with self.assertRaises(FrozenInstanceError):
            setattr(assessment, "risk_score", 50)

    def test_evaluate_all_sorting_descending(self) -> None:
        """Ensure evaluate_all sorts findings from highest to lowest risk."""
        finding_sqli_200 = self._create_finding(
            severity=Severity.HIGH, confidence=Confidence.HIGH
        )
        finding_xss_403 = self._create_finding(
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            attack_type="XSS",
        )
        finding_scan_404 = self._create_finding(
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            attack_type="SCAN",
        )

        pairs = [
            (finding_xss_403, self._create_log_event(403)),  # score: 60
            (finding_sqli_200, self._create_log_event(200)),  # score: 90
            (finding_scan_404, self._create_log_event(404)),  # score: 20
        ]

        assessments = self.evaluator.evaluate_all(pairs)

        self.assertEqual(len(assessments), 3)
        self.assertEqual(assessments[0].risk_score, 90)
        self.assertEqual(assessments[0].finding.attack_type, "SQL_INJECTION")
        self.assertEqual(assessments[1].risk_score, 60)
        self.assertEqual(assessments[1].finding.attack_type, "XSS")
        self.assertEqual(assessments[2].risk_score, 20)
        self.assertEqual(assessments[2].finding.attack_type, "SCAN")

    def test_module_level_convenience_functions(self) -> None:
        """Verify module-level calculate_risk_score and evaluate_risk match class behavior."""
        finding = self._create_finding(
            severity=Severity.HIGH, confidence=Confidence.HIGH
        )
        score = calculate_risk_score(finding, status_code=200)
        self.assertEqual(score, 90)

        assessment = evaluate_risk(finding, status_code=200)
        self.assertEqual(assessment.risk_score, 90)
        self.assertEqual(assessment.risk_level, Severity.CRITICAL)


if __name__ == "__main__":
    unittest.main()
