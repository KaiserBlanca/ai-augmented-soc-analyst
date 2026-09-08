"""Deterministic Cross-Site Scripting (XSS) detector.

This module implements deterministic detection rules for identifying Cross-Site Scripting
(XSS) injection attempts in web server request logs (primarily URI paths and query strings).

Detection Rationale:
    Cross-Site Scripting occurs when untrusted user input is reflected or stored in web
    pages without adequate sanitization or context-aware output encoding. Attackers inject
    malicious client-side scripts (JavaScript, HTML tags, event handlers) to execute within
    the victim's browser context.

Detection Strategy:
    1. Inspects normalized request URI paths and query string parameters (including URL-decoded text).
    2. Matches against targeted, explainable regex patterns representing recognized
       XSS vectors (explicit <script> blocks, JavaScript pseudo-protocols, dangerous
       HTML tags with event handlers, inline DOM event triggers, and exploit helper functions).
    3. Emits structured Finding objects documenting the matched evidence, technical
       security consequences, and organizational business risks.

Limitations & Assumptions:
    - Analyzes incoming HTTP request lines; does not analyze server response bodies.
    - An observed payload in access logs indicates an injection attempt; it does NOT prove
      that the target web application is vulnerable or that the script was executed in a client browser.
"""

from dataclasses import dataclass
import re
from typing import Optional
import urllib.parse

from soc_analyst.detection.base import BaseDetector
from soc_analyst.models.finding import Confidence, Finding, Severity
from soc_analyst.models.log_event import LogEvent


@dataclass(frozen=True)
class XSSPattern:
    """Represents a named XSS detection pattern with security context."""

    name: str
    pattern: re.Pattern[str]
    description: str
    confidence: Confidence


# Named, independently testable XSS detection patterns
XSS_PATTERNS: tuple[XSSPattern, ...] = (
    # 1. Direct Script Tags (e.g., "<script>", "<script src=...>", "</script>")
    # Behavior: Injects inline or external script execution blocks into the document DOM.
    XSSPattern(
        name="XSS_SCRIPT_TAG",
        pattern=re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE),
        description="Direct script tag injection intended to execute arbitrary JavaScript",
        confidence=Confidence.HIGH,
    ),
    # 2. JavaScript / VBScript / Data Pseudo-Protocols (e.g., "javascript:alert(1)", "data:text/html...")
    # Behavior: Executes scripts when parsed as clickable links, iframe sources, or redirection destinations.
    XSSPattern(
        name="XSS_PSEUDO_PROTOCOL",
        pattern=re.compile(r"\b(?:javascript|vbscript|data):\s*", re.IGNORECASE),
        description="URI pseudo-protocol scheme used to trigger script execution within link or frame contexts",
        confidence=Confidence.HIGH,
    ),
    # 3. Dangerous HTML Elements with Inline Event Handlers (e.g., "<img src=x onerror=...>", "<svg onload=...>")
    # Behavior: Injects markup with automated event triggers that run without user interaction.
    XSSPattern(
        name="XSS_EVENT_HANDLER_TAG",
        pattern=re.compile(
            r"<\s*(?:img|iframe|svg|body|object|embed|input|video|audio)\b[^>]*\bon\w+\s*=",
            re.IGNORECASE,
        ),
        description="HTML tag with inline event handler designed to execute scripts on load or error",
        confidence=Confidence.HIGH,
    ),
    # 4. Embedded Frames & External Object Injections (e.g., "<iframe src='http://evil.com'>", "<object ...>")
    # Behavior: Embeds external malicious resources, UI redress/clickjacking frames, or rogue documents.
    XSSPattern(
        name="XSS_DANGEROUS_TAG",
        pattern=re.compile(r"<\s*(?:iframe|object|embed)\b[^>]*>", re.IGNORECASE),
        description="Dangerous HTML element injection capable of embedding untrusted third-party content",
        confidence=Confidence.HIGH,
    ),
    # 5. Standalone DOM Event Attribute Assignment (e.g., "onerror=alert(1)", "onload=evil()")
    # Behavior: Injects attribute values into pre-existing HTML tags undergoing attribute reflection.
    XSSPattern(
        name="XSS_INLINE_EVENT_ATTRIBUTE",
        pattern=re.compile(
            r"\bon(?:load|error|click|mouseover|focus|blur|submit)\s*=\s*['\"]?[^'\">\s]+",
            re.IGNORECASE,
        ),
        description="Standalone inline DOM event handler assignment attempting attribute-level injection",
        confidence=Confidence.MEDIUM,
    ),
    # 6. Common Exploit Probes & Popup Triggers (e.g., "alert('XSS')", "confirm(1)", "document.cookie")
    # Behavior: Diagnostic and data-harvesting function calls widely utilized in proof-of-concept payloads.
    XSSPattern(
        name="XSS_POPUP_OR_COOKIE_FUNCTION",
        pattern=re.compile(
            r"(?:alert|prompt|confirm|eval)\s*\(\s*(?:['\"`]?\w*['\"`]?|document\.cookie)\s*\)",
            re.IGNORECASE,
        ),
        description="Classic XSS verification function call (alert/prompt/eval) targeting client execution",
        confidence=Confidence.HIGH,
    ),
)


class XSSDetector(BaseDetector):
    """Detector for identifying Cross-Site Scripting (XSS) attempts in HTTP log events.

    Inspects normalized request paths and query strings for characteristic XSS
    syntax patterns, emitting structured findings detailing technical impact
    and business risk.
    """

    @property
    def rule_id(self) -> str:
        """Unique rule identifier for XSS detections."""
        return "SEC-XSS-001"

    @property
    def attack_type(self) -> str:
        """Categorical classification of the threat."""
        return "XSS"

    @property
    def name(self) -> str:
        """Human-readable name of the detector."""
        return "Cross-Site Scripting Detector"

    def detect(self, event: LogEvent) -> list[Finding]:
        """Analyze a LogEvent for Cross-Site Scripting indicators.

        Evaluates both raw and URL-decoded forms of the request path. If an XSS
        payload pattern is matched, constructs a structured Finding object.

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
            for pattern_def in XSS_PATTERNS:
                match = pattern_def.pattern.search(candidate_str)
                if match:
                    matched_evidence = match.group(0).strip()
                    finding = Finding(
                        rule_id=self.rule_id,
                        attack_type=self.attack_type,
                        severity=Severity.MEDIUM,
                        confidence=pattern_def.confidence,
                        description=(
                            f"Potential Cross-Site Scripting (XSS) attempt observed in request: {pattern_def.description}."
                        ),
                        evidence=f"[{pattern_def.name}] Matched: '{matched_evidence}' in '{target_text}'",
                        technical_impact=(
                            "An attacker may execute arbitrary client-side JavaScript in victim browser sessions, "
                            "enabling session hijacking via cookie theft, credential harvesting through injected forms, or client-side defacement."
                        ),
                        business_impact=(
                            "If exploited against authenticated users or administrators, the vulnerability may facilitate account takeover, "
                            "fraudulent user-authorized actions, compromise of confidential corporate portals, and brand erosion."
                        ),
                        source_ip=event.source_ip,
                        timestamp=event.timestamp,
                        recommended_action=(
                            "Verify whether the affected endpoint renders user input without context-aware HTML entity encoding. "
                            "Deploy or strengthen a Content Security Policy (CSP) header prohibiting inline script execution ('unsafe-inline')."
                        ),
                    )
                    findings.append(finding)
                    return findings

        return findings
