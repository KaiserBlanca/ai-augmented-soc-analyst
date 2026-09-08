"""Deterministic risk evaluation engine for security findings.

This module evaluates structured security findings against contextual telemetry
(such as HTTP response status codes) to produce a normalized 0-100 dynamic Risk Score.

Methodology:
    In alignment with SOC triage standards and defensible cybersecurity risk modeling,
    the Risk Score reflects three distinct, explainable dimensions:

    1. Inherent Threat Severity (0-50 points):
       Measures the potential technical and business damage if the attack vector succeeds.
       - CRITICAL: 50 points (e.g., Remote Code Execution)
       - HIGH:     40 points (e.g., SQL Injection, unauthorized data access)
       - MEDIUM:   25 points (e.g., Cross-Site Scripting, sensitive info exposure)
       - LOW:      10 points (e.g., Reconnaissance, generic scanner probes)

    2. Detection Confidence (0-30 points):
       Measures certainty that the detected telemetry represents genuine malicious activity.
       - HIGH:     30 points (Explicit exploit signatures, unambiguous syntax)
       - MEDIUM:   20 points (Comment truncation, heuristic patterns)
       - LOW:      10 points (Broad pattern match, potential benign ambiguity)

    3. HTTP Response Status Code Outcome (0-20 points):
       Contextual indicator of whether the target application processed, rejected,
       or errored on the payload.
       - HTTP 200-299 (Success):   +20 points (Payload bypassed filters and was executed by the app)
       - HTTP 500-599 (Error):     +15 points (Unhandled exception, potential database/interpreter crash)
       - HTTP 300-399 (Redirect):  +10 points (Redirected response, potential reflection or open redirect)
       - HTTP 401/403/400 (Block): +5 points  (Access denied / rejected at boundary)
       - HTTP 404 (Not Found):      0 points  (Target resource non-existent; zero compromise potential)
       - Unknown / Missing:        +5 points  (Neutral baseline)

    Total Risk Score:
        score = Severity Points + Confidence Points + Status Code Points (Clamped to 0-100)
"""

from collections.abc import Iterable
from dataclasses import dataclass
import logging
from typing import Optional

from soc_analyst.models.finding import Confidence, Finding, Severity
from soc_analyst.models.log_event import LogEvent

logger = logging.getLogger(__name__)

# Point allocations for Severity
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 50,
    Severity.HIGH: 40,
    Severity.MEDIUM: 25,
    Severity.LOW: 10,
}

# Point allocations for Confidence
CONFIDENCE_WEIGHTS: dict[Confidence, int] = {
    Confidence.HIGH: 30,
    Confidence.MEDIUM: 20,
    Confidence.LOW: 10,
}


@dataclass(frozen=True)
class RiskAssessment:
    """Immutable evaluation model capturing comprehensive risk metrics for a finding.

    Attributes:
        finding: The underlying security finding being assessed.
        risk_score: Normalized numerical risk score from 0 to 100.
        risk_level: Categorical risk tier (LOW, MEDIUM, HIGH, CRITICAL).
        status_code: Evaluated HTTP response status code, if available.
        severity_points: Inherent severity contribution (0-50).
        confidence_points: Detection confidence contribution (0-30).
        status_code_modifier: Contextual HTTP outcome contribution (0-20).
        rationale: Explanatory rationale detailing how the score was calculated.
    """

    finding: Finding
    risk_score: int
    risk_level: Severity
    status_code: Optional[int]
    severity_points: int
    confidence_points: int
    status_code_modifier: int
    rationale: str


def _map_risk_level(score: int) -> Severity:
    """Map a 0-100 risk score into a qualitative risk tier.

    Args:
        score: Clamped integer risk score.

    Returns:
        Categorical Severity enum (LOW, MEDIUM, HIGH, CRITICAL).
    """
    if score >= 85:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    return Severity.LOW


def _calculate_status_code_modifier(status_code: Optional[int]) -> int:
    """Compute risk modifier points based on the HTTP response status code.

    In web security analysis, an attack receiving a 200 OK is significantly more
    hazardous than one receiving 403 Forbidden (blocked) or 404 Not Found (missing target).

    Args:
        status_code: HTTP status code, or None if unavailable.

    Returns:
        Point modifier between 0 and 20.
    """
    if status_code is None:
        return 5

    # 2xx: Request successfully processed by application
    if 200 <= status_code < 300:
        return 20

    # 5xx: Server internal error (potential SQL/interpreter syntax error or crash)
    if 500 <= status_code < 600:
        return 15

    # 3xx: Redirection
    if 300 <= status_code < 400:
        return 10

    # 404: Endpoint not found (target does not exist)
    if status_code == 404:
        return 0

    # 401 / 403 / 400: Rejected or unauthorized by server boundary
    if status_code in (400, 401, 403):
        return 5

    # Other 4xx client errors
    if 400 <= status_code < 500:
        return 5

    return 5


class RiskEvaluator:
    """Deterministic risk evaluation engine for SOC security telemetry.

    Calculates transparent, defensible risk scores (0-100) by combining
    threat severity, detection confidence, and contextual HTTP response codes.
    """

    def calculate_score(
        self,
        finding: Finding,
        log_event: Optional[LogEvent] = None,
        status_code: Optional[int] = None,
    ) -> int:
        """Calculate the 0-100 numerical risk score for a finding and event context.

        Args:
            finding: The security finding to evaluate.
            log_event: Optional LogEvent associated with the finding.
            status_code: Optional explicit HTTP status code (overrides log_event if provided).

        Returns:
            Normalized risk score between 0 and 100.
        """
        # Resolve status code from explicit parameter or from log_event
        resolved_status = (
            status_code
            if status_code is not None
            else (log_event.status_code if log_event else None)
        )

        sev_pts = SEVERITY_WEIGHTS.get(finding.severity, 10)
        conf_pts = CONFIDENCE_WEIGHTS.get(finding.confidence, 10)
        status_pts = _calculate_status_code_modifier(resolved_status)

        raw_score = sev_pts + conf_pts + status_pts
        return max(0, min(100, raw_score))

    def evaluate(
        self,
        finding: Finding,
        log_event: Optional[LogEvent] = None,
        status_code: Optional[int] = None,
    ) -> RiskAssessment:
        """Perform full risk assessment producing a detailed RiskAssessment object.

        Args:
            finding: The security finding to evaluate.
            log_event: Optional LogEvent providing context.
            status_code: Optional explicit HTTP status code override.

        Returns:
            Structured RiskAssessment instance detailing score breakdown and rationale.
        """
        resolved_status = (
            status_code
            if status_code is not None
            else (log_event.status_code if log_event else None)
        )

        sev_pts = SEVERITY_WEIGHTS.get(finding.severity, 10)
        conf_pts = CONFIDENCE_WEIGHTS.get(finding.confidence, 10)
        status_pts = _calculate_status_code_modifier(resolved_status)

        risk_score = max(0, min(100, sev_pts + conf_pts + status_pts))
        risk_level = _map_risk_level(risk_score)

        status_desc = (
            f"HTTP {resolved_status}"
            if resolved_status is not None
            else "Unknown status"
        )
        rationale = (
            f"Severity {finding.severity.value} ({sev_pts} pts) + "
            f"Confidence {finding.confidence.value} ({conf_pts} pts) + "
            f"Outcome {status_desc} ({status_pts} pts) = {risk_score}/100"
        )

        return RiskAssessment(
            finding=finding,
            risk_score=risk_score,
            risk_level=risk_level,
            status_code=resolved_status,
            severity_points=sev_pts,
            confidence_points=conf_pts,
            status_code_modifier=status_pts,
            rationale=rationale,
        )

    def evaluate_all(
        self,
        finding_event_pairs: Iterable[tuple[Finding, Optional[LogEvent]]],
    ) -> list[RiskAssessment]:
        """Evaluate risk across multiple finding-event pairs.

        Args:
            finding_event_pairs: Iterable sequence of (Finding, Optional[LogEvent]) tuples.

        Returns:
            List of RiskAssessment instances sorted in descending order of risk score.
        """
        assessments: list[RiskAssessment] = []
        for finding, event in finding_event_pairs:
            assessments.append(self.evaluate(finding, log_event=event))

        # Sort findings by risk score descending (highest risk first)
        assessments.sort(key=lambda a: a.risk_score, reverse=True)
        return assessments


# Default evaluator singleton instance
_default_evaluator = RiskEvaluator()


def calculate_risk_score(
    finding: Finding,
    log_event: Optional[LogEvent] = None,
    status_code: Optional[int] = None,
) -> int:
    """Calculate the numerical risk score using the default RiskEvaluator.

    Args:
        finding: The Finding to score.
        log_event: Optional LogEvent context.
        status_code: Optional status code override.

    Returns:
        Integer risk score between 0 and 100.
    """
    return _default_evaluator.calculate_score(
        finding, log_event=log_event, status_code=status_code
    )


def evaluate_risk(
    finding: Finding,
    log_event: Optional[LogEvent] = None,
    status_code: Optional[int] = None,
) -> RiskAssessment:
    """Evaluate full risk assessment using the default RiskEvaluator.

    Args:
        finding: The Finding to evaluate.
        log_event: Optional LogEvent context.
        status_code: Optional status code override.

    Returns:
        RiskAssessment dataclass instance.
    """
    return _default_evaluator.evaluate(
        finding, log_event=log_event, status_code=status_code
    )
