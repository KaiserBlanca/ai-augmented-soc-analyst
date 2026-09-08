"""Structured security finding models, enums, and evaluation contracts."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Potential organizational and technical impact if the detected threat is real.

    Severity measures the magnitude of consequence, not the certainty of the attack.
    For instance, a SQL injection attempt has a HIGH severity potential even if confidence
    is MEDIUM due to unverified target vulnerability.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """Certainty level indicating how reliably the detected pattern reflects genuine malicious activity.

    Confidence distinguishes between high-fidelity attacks and ambiguous or benign-matching
    anomalies (e.g., broad regex matches vs. definitive multi-indicator exploits).
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass(frozen=True)
class Finding:
    """Represents an immutable, structured security finding produced by detection engines.

    A Finding bundles forensic evidence, risk assessment (severity vs confidence),
    impact analysis (technical and business), and optional AI enrichment into a coherent
    unit for analyst review and reporting.

    Attributes:
        rule_id: Unique identifier for the triggering detection rule (e.g., 'SEC-SQLI-001').
        attack_type: Categorical identifier of the threat (e.g., 'SQL_INJECTION', 'XSS', 'BRUTE_FORCE').
        severity: Potential impact or damage level if the attack were realized.
        confidence: Certainty level indicating how likely the activity is genuinely malicious.
        description: Human-readable explanation of why this finding was flagged.
        evidence: Concrete forensic evidence (e.g., matched regex, malicious payload string, failure count).
        technical_impact: Direct technical consequences on affected systems if successful.
        business_impact: Potential operational, financial, legal, or reputational risks to the business.
        source_ip: Originating IP address or host associated with the activity, if identified.
        timestamp: Recorded event timestamp or detection time.
        recommended_action: Suggested immediate remediation or triage steps for the SOC analyst.
        ai_enrichment: Contextual analysis, threat insights, or response playbooks provided by AI.
    """

    rule_id: str
    attack_type: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    technical_impact: str
    business_impact: str
    source_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    recommended_action: Optional[str] = None
    ai_enrichment: Optional[str] = None
