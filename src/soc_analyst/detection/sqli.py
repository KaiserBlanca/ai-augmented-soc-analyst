"""Deterministic SQL Injection (SQLi) detector.

This module implements deterministic detection rules for identifying SQL injection
attempts in web server telemetry (e.g. URI query strings and request paths).

Detection Rationale:
    SQL injection occurs when untrusted user input is concatenated directly into
    database command interpreters. Attackers exploit this to bypass authentication,
    extract sensitive data, modify database structures, or execute administrative commands.

Detection Strategy:
    1. Inspects request URI path and query string parameters (with URL-decoding).
    2. Matches against targeted, explainable regex patterns representing common
       SQLi attack vectors (Boolean tautologies, UNION SELECT, stacked queries,
       comment truncations, and time-based blind injection functions).
    3. Produces structured Finding objects detailing matched evidence, technical
       security impact, and potential business risk.

Limitations & Assumptions:
    - Assumes suspicious payloads appear in the HTTP request URI or query string.
    - POST request bodies are not visible in standard web access logs.
    - A matched attempt indicates malicious intent or testing; it does NOT confirm
      that the backend application is actually vulnerable or successfully compromised.
"""

from dataclasses import dataclass
import re
from typing import Optional
import urllib.parse

from soc_analyst.detection.base import BaseDetector
from soc_analyst.models.finding import Confidence, Finding, Severity
from soc_analyst.models.log_event import LogEvent


@dataclass(frozen=True)
class SQLiPattern:
    """Represents a named SQL injection detection pattern with security rationale."""

    name: str
    pattern: re.Pattern[str]
    description: str
    confidence: Confidence


# Named, independently testable SQL injection detection patterns
# Ordered from most specific (e.g. UNION SELECT, Time-based blind, Stacked) to generic (Comments)
SQLI_PATTERNS: tuple[SQLiPattern, ...] = (
    # 1. UNION-based Extraction (e.g., "UNION SELECT ...", "UNION ALL SELECT ...")
    # Behavior: Appends attacker-controlled SELECT query to extract data from unauthorized tables.
    SQLiPattern(
        name="SQLI_UNION_SELECT",
        pattern=re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),
        description="UNION-based data extraction technique querying arbitrary database tables",
        confidence=Confidence.HIGH,
    ),
    # 2. Time-based Blind Functions (e.g., "SLEEP(5)", "BENCHMARK(5000000,...)", "WAITFOR DELAY")
    # Behavior: Triggers intentional time delays to extract data when no error messages are returned.
    SQLiPattern(
        name="SQLI_TIME_BASED_BLIND",
        pattern=re.compile(
            r"\b(?:WAITFOR\s+DELAY|SLEEP\s*\(\s*\d+\s*\)|BENCHMARK\s*\(\s*\d+|PG_SLEEP\s*\(\s*\d+\s*\))",
            re.IGNORECASE,
        ),
        description="Time-based blind SQL injection probe measuring backend response latency",
        confidence=Confidence.HIGH,
    ),
    # 3. Stacked Queries & Dangerous DDL/DML (e.g., "; DROP TABLE ...", "; DELETE FROM ...")
    # Behavior: Terminates primary query and initiates an unauthorized secondary statement.
    SQLiPattern(
        name="SQLI_STACKED_QUERIES",
        pattern=re.compile(
            r";\s*(?:DROP\s+TABLE|ALTER\s+TABLE|DELETE\s+FROM|UPDATE\s+\w+\s+SET|INSERT\s+INTO|EXEC\s+(?:xp_|sp_))\b",
            re.IGNORECASE,
        ),
        description="Stacked query attempt targeting schema destruction or arbitrary modification",
        confidence=Confidence.HIGH,
    ),
    # 4. Boolean-based Tautology (e.g., "' OR '1'='1", "OR 1=1", "AND true")
    # Behavior: Forces WHERE clauses to evaluate to True to bypass auth or dump tables.
    SQLiPattern(
        name="SQLI_BOOLEAN_TAUTOLOGY",
        pattern=re.compile(
            r"\b(?:OR|AND)\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1['\"]?|"
            r"\b(?:OR|AND)\s+(?:1\s*=\s*1|true\b)",
            re.IGNORECASE,
        ),
        description="Boolean tautology attempt designed to force SQL query conditions to true",
        confidence=Confidence.HIGH,
    ),
    # 5. SQL Comment Injection (e.g., "admin'--", "' /*", "' #")
    # Behavior: Truncates subsequent query logic, neutralizing password verification or filters.
    SQLiPattern(
        name="SQLI_COMMENT_INJECTION",
        pattern=re.compile(r"['\"][^'\"]*(?:--|#|/\*)", re.IGNORECASE),
        description="SQL comment syntax used to truncate and neutralize remaining query logic",
        confidence=Confidence.MEDIUM,
    ),
)


class SQLInjectionDetector(BaseDetector):
    """Detector for identifying SQL Injection (SQLi) attempts in HTTP log events.

    Inspects normalized request paths and query strings for characteristic SQLi
    syntax patterns, emitting structured findings that detail technical impact
    and business risk.
    """

    @property
    def rule_id(self) -> str:
        """Unique rule identifier for SQL Injection detections."""
        return "SEC-SQLI-001"

    @property
    def attack_type(self) -> str:
        """Categorical classification of the threat."""
        return "SQL_INJECTION"

    @property
    def name(self) -> str:
        """Human-readable name of the detector."""
        return "SQL Injection Detector"

    def detect(self, event: LogEvent) -> list[Finding]:
        """Analyze a LogEvent for SQL injection indicators.

        Evaluates both raw and URL-decoded forms of the request path. If a known
        SQLi signature is matched, constructs a structured Finding preserving
        forensic evidence.

        Args:
            event: Normalized LogEvent instance to evaluate.

        Returns:
            List containing generated Finding objects, or empty list if no threats detected.
        """
        target_text: Optional[str] = event.path or event.raw_line
        if not target_text:
            return []

        # Evaluate canonical URL-decoded target first to detect obfuscated vectors
        decoded_text = urllib.parse.unquote_plus(target_text)
        candidates: list[str] = [decoded_text]
        if decoded_text != target_text:
            candidates.append(target_text)

        findings: list[Finding] = []

        for candidate_str in candidates:
            for pattern_def in SQLI_PATTERNS:
                match = pattern_def.pattern.search(candidate_str)
                if match:
                    matched_evidence = match.group(0).strip()
                    finding = Finding(
                        rule_id=self.rule_id,
                        attack_type=self.attack_type,
                        severity=Severity.HIGH,
                        confidence=pattern_def.confidence,
                        description=(
                            f"Potential SQL Injection attempt observed in request: {pattern_def.description}."
                        ),
                        evidence=f"[{pattern_def.name}] Matched: '{matched_evidence}' in '{target_text}'",
                        technical_impact=(
                            "An attacker may manipulate backend database queries, potentially leading to "
                            "unauthorized data exfiltration, authentication bypass, data manipulation, or schema corruption."
                        ),
                        business_impact=(
                            "If successful, the attack could expose sensitive customer data, breach regulatory "
                            "mandates (e.g. GDPR, KVKK, PCI-DSS), incur substantial financial penalties, and damage organizational trust."
                        ),
                        source_ip=event.source_ip,
                        timestamp=event.timestamp,
                        recommended_action=(
                            "Inspect application query execution logs for related database errors or data dumps. "
                            "Ensure all SQL statements on the endpoint utilize parameterized queries (prepared statements) or ORM abstractions."
                        ),
                    )
                    findings.append(finding)
                    return findings

        return findings
