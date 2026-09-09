"""AI enrichment module utilizing Google Gemini API for contextual security analysis.

This module consumes high-risk Finding domain objects and LogEvent telemetry,
transmitting structured, data-minimized prompts to the Google Gemini API (gemini-3.6-flash)
via the official `google-genai` SDK.

The LLM enriches the technical finding with three distinct perspectives:
    1. Executive Summary: High-level overview explaining business impact for leadership.
    2. Root Cause Analysis: Technical dissection of the attack payload and exploitation mechanics.
    3. Remediation Playbook: Actionable containment and prevention steps for SOC analysts.

Fault Tolerance & Graceful Degradation:
    In alignment with ADR-001 and project rules, AI enrichment is strictly supplementary.
    If GEMINI_API_KEY is absent, quotas are exceeded, or network failures occur,
    the enricher degrades gracefully by returning a deterministic local fallback analysis
    without raising uncaught exceptions or interrupting the pipeline.
"""

from dataclasses import dataclass, replace
import logging
import os
import re
from typing import Optional

from dotenv import load_dotenv
from google import genai
from google.genai import errors

from soc_analyst.models.finding import Finding
from soc_analyst.models.log_event import LogEvent

# Ensure environment variables from .env are loaded
load_dotenv()

logger = logging.getLogger(__name__)

DEFAULT_MODEL: str = "gemini-3.6-flash"


@dataclass(frozen=True)
class EnrichmentResult:
    """Container for AI-generated threat enrichment analysis.

    Attributes:
        executive_summary: High-level management summary of the incident.
        root_cause_analysis: Technical breakdown of the vulnerability and payload mechanics.
        remediation_playbook: Step-by-step guidance for containment and long-term resolution.
        raw_response: Full text output returned by the model or fallback generator.
        is_fallback: True if output was generated locally due to API failure or missing credentials.
        error_message: Optional diagnostic error message if fallback mode was engaged.
    """

    executive_summary: str
    root_cause_analysis: str
    remediation_playbook: str
    raw_response: str
    is_fallback: bool = False
    error_message: Optional[str] = None

    def to_formatted_string(self) -> str:
        """Format the enrichment into a standardized markdown block."""
        fallback_notice = (
            "*(Generated via Deterministic Fallback — External AI Unavailable)*\n\n"
            if self.is_fallback
            else ""
        )
        return (
            f"{fallback_notice}"
            f"### Executive Summary\n{self.executive_summary}\n\n"
            f"### Root Cause Analysis\n{self.root_cause_analysis}\n\n"
            f"### Remediation Playbook\n{self.remediation_playbook}"
        )


def _build_prompt(
    finding: Finding,
    log_event: Optional[LogEvent] = None,
    risk_score: Optional[int] = None,
) -> str:
    """Construct a structured, minimized prompt for the Gemini model.

    Adheres to data-minimization policies by excluding raw full log files,
    authorizations, or private session tokens, focusing strictly on relevant telemetry.

    Args:
        finding: The detected security finding.
        log_event: Optional LogEvent providing HTTP metadata.
        risk_score: Calculated risk score (0-100) if evaluated.

    Returns:
        Structured prompt string.
    """
    http_method = log_event.method if log_event and log_event.method else "N/A"
    path = log_event.path if log_event and log_event.path else "N/A"
    status_code = (
        str(log_event.status_code)
        if log_event and log_event.status_code is not None
        else "N/A"
    )
    score_str = f"{risk_score}/100" if risk_score is not None else "Not evaluated"

    return f"""You are a Principal SOC Analyst and Cyber Incident Responder assisting in automated triage.
Analyze the following verified security finding and provide a rigorous, concise analysis.

--- TELEMETRY CONTEXT ---
- Attack Category: {finding.attack_type}
- Inherent Severity: {finding.severity.value}
- Detection Confidence: {finding.confidence.value}
- Dynamic Risk Score: {score_str}
- HTTP Method: {http_method}
- Target URI / Path: {path}
- HTTP Response Status: {status_code}
- Forensic Evidence: {finding.evidence}
- Stated Technical Impact: {finding.technical_impact}
- Stated Business Risk: {finding.business_impact}

--- INSTRUCTIONS ---
Format your response strictly using these three markdown headings:

### Executive Summary
Provide a 2-3 sentence strategic summary for executive stakeholders and CISOs: what occurred, asset exposure risk, and organizational impact.

### Root Cause Analysis
Explain the exact technical mechanism: why this payload targets the system, how the syntax exploits backend interpreters or browsers, and whether the observed status code indicates success or mitigation.

### Remediation Playbook
Provide concrete, prioritized response steps:
1. Immediate containment & triage (e.g. log correlation, IP restrictions).
2. Code-level remediation (e.g. prepared statements, context-aware encoding, CSP).
3. Verification & monitoring recommendations.
"""


def _parse_ai_response(text: str) -> tuple[str, str, str]:
    """Parse the model's generated text into three distinct sections.

    Args:
        text: Raw response string from Gemini.

    Returns:
        Tuple of (executive_summary, root_cause_analysis, remediation_playbook).
    """
    cleaned = text.strip()

    exec_pattern = re.compile(
        r"(?:###|\*\*|#)?\s*Executive Summary\s*(?:###|\*\*|#)?\s*\n(.*?)(?=(?:###|\*\*|#)?\s*Root Cause Analysis|\Z)",
        re.DOTALL | re.IGNORECASE,
    )
    rca_pattern = re.compile(
        r"(?:###|\*\*|#)?\s*Root Cause Analysis\s*(?:###|\*\*|#)?\s*\n(.*?)(?=(?:###|\*\*|#)?\s*Remediation Playbook|\Z)",
        re.DOTALL | re.IGNORECASE,
    )
    rem_pattern = re.compile(
        r"(?:###|\*\*|#)?\s*Remediation Playbook\s*(?:###|\*\*|#)?\s*\n(.*)",
        re.DOTALL | re.IGNORECASE,
    )

    exec_match = exec_pattern.search(cleaned)
    rca_match = rca_pattern.search(cleaned)
    rem_match = rem_pattern.search(cleaned)

    exec_summary = exec_match.group(1).strip() if exec_match else ""
    root_cause = rca_match.group(1).strip() if rca_match else ""
    remediation = rem_match.group(1).strip() if rem_match else ""

    # If headers were omitted, populate summary and default remaining sections
    if not exec_summary and not root_cause and not remediation:
        exec_summary = cleaned
        root_cause = (
            "Technical details provided in executive overview above."
        )
        remediation = (
            "Follow standard organizational incident response playbooks."
        )

    return exec_summary, root_cause, remediation


def _generate_fallback_enrichment(
    finding: Finding,
    log_event: Optional[LogEvent] = None,
    risk_score: Optional[int] = None,
    reason: str = "AI service unavailable",
) -> EnrichmentResult:
    """Generate a high-quality deterministic fallback analysis when API is inaccessible.

    Args:
        finding: The finding being evaluated.
        log_event: Optional log event.
        risk_score: Optional risk score.
        reason: Explanation of why fallback was engaged.

    Returns:
        EnrichmentResult marked as is_fallback=True.
    """
    score_display = f" (Risk Score: {risk_score}/100)" if risk_score else ""
    target_path = (
        f" targeting '{log_event.path}'"
        if log_event and log_event.path
        else ""
    )
    status_note = (
        f" The server responded with HTTP {log_event.status_code}."
        if log_event and log_event.status_code is not None
        else ""
    )

    exec_summary = (
        f"Automated detection flagged a {finding.severity.value} severity {finding.attack_type} attempt{score_display}{target_path}. "
        f"Deterministic signatures confirmed suspicious activity locally without external AI validation.{status_note} "
        f"Business exposure: {finding.business_impact}"
    )

    root_cause = (
        f"The incoming request contained recognized attack patterns: {finding.evidence}. "
        f"Technical vulnerability impact: {finding.technical_impact}"
    )

    recommended = (
        finding.recommended_action
        if finding.recommended_action
        else "Apply strict input validation and defense-in-depth controls."
    )
    ip_note = (
        f" Block or rate-limit source IP '{finding.source_ip}' if repeat probes persist."
        if finding.source_ip
        else ""
    )

    remediation = (
        f"1. Triage: Inspect application and backend query logs around {finding.timestamp or 'the event timestamp'} to determine if execution succeeded.\n"
        f"2. Mitigation: {recommended}\n"
        f"3. Containment:{ip_note} Ensure WAF rules block identical payload signatures."
    )

    raw_response = (
        f"### Executive Summary\n{exec_summary}\n\n"
        f"### Root Cause Analysis\n{root_cause}\n\n"
        f"### Remediation Playbook\n{remediation}"
    )

    return EnrichmentResult(
        executive_summary=exec_summary,
        root_cause_analysis=root_cause,
        remediation_playbook=remediation,
        raw_response=raw_response,
        is_fallback=True,
        error_message=reason,
    )


class GeminiEnricher:
    """AI enrichment client utilizing Google Gemini API (gemini-3.6-flash).

    Provides deep context, root cause breakdowns, and actionable remediation steps
    for security findings while guaranteeing zero crash failures through robust fallbacks.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
    ) -> None:
        """Initialize the Gemini enrichment service.

        Args:
            api_key: Optional Gemini API key. Defaults to GEMINI_API_KEY environment variable.
            model: Gemini model identifier (defaults to 'gemini-3.6-flash').
        """
        self.model = model
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        self._client: Optional[genai.Client] = None
        if self.api_key:
            try:
                self._client = genai.Client(api_key=self.api_key)
            except Exception as err:
                logger.warning(
                    "Failed to initialize Google GenAI Client (%s). Running in fallback mode.",
                    err,
                )
                self._client = None
        else:
            logger.info(
                "GEMINI_API_KEY not configured. GeminiEnricher will operate in deterministic fallback mode."
            )

    def enrich(
        self,
        finding: Finding,
        log_event: Optional[LogEvent] = None,
        risk_score: Optional[int] = None,
    ) -> EnrichmentResult:
        """Enrich a security finding with AI-generated analysis.

        Connects to the Gemini API and parses the response into executive summary,
        root cause analysis, and remediation steps. If the API key is missing or
        an API error occurs (e.g. quota, timeout), gracefully returns fallback analysis.

        Args:
            finding: The security finding to enrich.
            log_event: Optional LogEvent providing contextual details.
            risk_score: Optional evaluated numerical risk score.

        Returns:
            EnrichmentResult containing structured analysis and fallback status.
        """
        if self._client is None:
            return _generate_fallback_enrichment(
                finding,
                log_event=log_event,
                risk_score=risk_score,
                reason="GEMINI_API_KEY is not configured or client failed initialization.",
            )

        prompt = _build_prompt(finding, log_event=log_event, risk_score=risk_score)

        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
            raw_text = response.text or ""
            exec_summary, root_cause, remediation = _parse_ai_response(raw_text)

            return EnrichmentResult(
                executive_summary=exec_summary,
                root_cause_analysis=root_cause,
                remediation_playbook=remediation,
                raw_response=raw_text,
                is_fallback=False,
                error_message=None,
            )

        except errors.APIError as err:
            logger.warning(
                "Gemini API error encountered (%s). Engaging deterministic fallback.",
                err,
            )
            return _generate_fallback_enrichment(
                finding,
                log_event=log_event,
                risk_score=risk_score,
                reason=f"Google GenAI API Error: {err}",
            )
        except Exception as err:
            logger.warning(
                "Unexpected failure during Gemini enrichment (%s). Engaging fallback.",
                err,
            )
            return _generate_fallback_enrichment(
                finding,
                log_event=log_event,
                risk_score=risk_score,
                reason=f"Enrichment exception ({type(err).__name__}): {err}",
            )

    def enrich_finding(
        self,
        finding: Finding,
        log_event: Optional[LogEvent] = None,
        risk_score: Optional[int] = None,
    ) -> Finding:
        """Enrich a finding and return a new Finding object with ai_enrichment field populated.

        Preserves immutability of the original Finding instance.

        Args:
            finding: The finding to enrich.
            log_event: Optional LogEvent context.
            risk_score: Optional risk score.

        Returns:
            A new Finding instance with updated ai_enrichment string.
        """
        result = self.enrich(
            finding, log_event=log_event, risk_score=risk_score
        )
        return replace(finding, ai_enrichment=result.to_formatted_string())


# Convenience module-level enrich function
def enrich_finding(
    finding: Finding,
    log_event: Optional[LogEvent] = None,
    risk_score: Optional[int] = None,
    api_key: Optional[str] = None,
    model: str = DEFAULT_MODEL,
) -> Finding:
    """Enrich a Finding instance using a dynamically configured GeminiEnricher.

    Args:
        finding: Finding to enrich.
        log_event: Optional LogEvent context.
        risk_score: Optional risk score.
        api_key: Optional API key override.
        model: Model name override.

    Returns:
        Updated Finding instance containing AI analysis.
    """
    enricher = GeminiEnricher(api_key=api_key, model=model)
    return enricher.enrich_finding(
        finding, log_event=log_event, risk_score=risk_score
    )
