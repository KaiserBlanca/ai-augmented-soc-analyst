"""Unit tests for GeminiEnricher utilizing unittest.mock.

Verifies API interaction, structured prompt construction, section parsing,
and deterministic fallback behaviors (missing API key, quota exhaustion, network failures)
without requiring live external network access.
"""

from datetime import datetime, timezone
import os
import unittest
from unittest.mock import MagicMock, patch

from google.genai import errors

from soc_analyst.ai.enricher import (
    DEFAULT_MODEL,
    EnrichmentResult,
    GeminiEnricher,
    _build_prompt,
    _parse_ai_response,
    enrich_finding,
)
from soc_analyst.models.finding import Confidence, Finding, Severity
from soc_analyst.models.log_event import LogEvent


class TestAIEnricher(unittest.TestCase):
    """Test suite for AI enrichment, prompt formatting, and defensive fallback logic."""

    def setUp(self) -> None:
        """Create sample finding and event instances for testing."""
        self.finding = Finding(
            rule_id="SEC-SQLI-001",
            attack_type="SQL_INJECTION",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Potential SQL Injection in product query",
            evidence="[SQLI_UNION_SELECT] Matched: 'UNION SELECT' in '/catalog?id=1 UNION SELECT 1,2,3--'",
            technical_impact="Unauthorized database query execution and data exfiltration",
            business_impact="Exposure of customer records and GDPR compliance penalties",
            source_ip="198.51.100.42",
            timestamp=datetime(2026, 10, 10, 14, 0, 0, tzinfo=timezone.utc),
            recommended_action="Use parameterized SQL queries across all catalog endpoints",
        )
        self.log_event = LogEvent(
            raw_line="raw log string",
            source_ip="198.51.100.42",
            method="GET",
            path="/catalog?id=1 UNION SELECT 1,2,3--",
            status_code=200,
            timestamp=datetime(2026, 10, 10, 14, 0, 0, tzinfo=timezone.utc),
        )

    # -------------------------------------------------------------------------
    # 1. Prompt Construction & Parsing Unit Tests
    # -------------------------------------------------------------------------

    def test_build_prompt_contains_telemetry(self) -> None:
        """Ensure prompt includes relevant telemetry context while maintaining data minimization."""
        prompt = _build_prompt(
            self.finding, log_event=self.log_event, risk_score=90
        )

        self.assertIn("SQL_INJECTION", prompt)
        self.assertIn("HIGH", prompt)
        self.assertIn("90/100", prompt)
        self.assertIn("UNION SELECT", prompt)
        self.assertIn("HTTP Method: GET", prompt)
        self.assertIn("HTTP Response Status: 200", prompt)
        self.assertIn("Executive Summary", prompt)
        self.assertIn("Root Cause Analysis", prompt)
        self.assertIn("Remediation Playbook", prompt)

    def test_parse_ai_response_sections(self) -> None:
        """Ensure AI markdown response is accurately split into three structured sections."""
        raw_ai_text = """
### Executive Summary
A critical SQL injection exploit was attempted against the catalog endpoint.

### Root Cause Analysis
Untrusted URI parameter values were concatenated directly into the backend SQL statement.

### Remediation Playbook
1. Isolate the server.
2. Implement prepared statements.
3. Review audit logs.
"""
        exec_s, rca, rem = _parse_ai_response(raw_ai_text)

        self.assertIn("A critical SQL injection exploit was attempted", exec_s)
        self.assertIn("Untrusted URI parameter values were concatenated", rca)
        self.assertIn("Implement prepared statements", rem)

    def test_parse_ai_response_without_headers(self) -> None:
        """Ensure unformatted AI text degrades to populating executive summary without crashing."""
        raw_ai_text = "Plain response text without specific markdown headers."
        exec_s, rca, rem = _parse_ai_response(raw_ai_text)

        self.assertEqual(exec_s, raw_ai_text)
        self.assertTrue(len(rca) > 0)
        self.assertTrue(len(rem) > 0)

    # -------------------------------------------------------------------------
    # 2. Mocked Successful API Interactions
    # -------------------------------------------------------------------------

    @patch("soc_analyst.ai.enricher.genai.Client")
    def test_enrich_success_with_mocked_gemini(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Test successful enrichment flow via mocked Google GenAI client."""
        # Setup mock client and response
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_response = MagicMock()
        mock_response.text = """
### Executive Summary
High-risk SQL injection targeting catalog database.

### Root Cause Analysis
Vulnerable parameter reflection in database query.

### Remediation Playbook
1. Patch catalog SQL query.
2. Verify WAF rules.
"""
        mock_client.models.generate_content.return_value = mock_response

        enricher = GeminiEnricher(api_key="mock_test_key")
        result = enricher.enrich(
            self.finding, log_event=self.log_event, risk_score=90
        )

        self.assertIsInstance(result, EnrichmentResult)
        self.assertFalse(result.is_fallback)
        self.assertIsNone(result.error_message)
        self.assertIn("High-risk SQL injection", result.executive_summary)
        self.assertIn("Vulnerable parameter", result.root_cause_analysis)
        self.assertIn("Patch catalog SQL query", result.remediation_playbook)

        # Verify correct model and prompt invocation
        mock_client.models.generate_content.assert_called_once()
        call_kwargs = mock_client.models.generate_content.call_args.kwargs
        self.assertEqual(call_kwargs["model"], DEFAULT_MODEL)
        self.assertIn("SQL_INJECTION", call_kwargs["contents"])

    @patch("soc_analyst.ai.enricher.genai.Client")
    def test_enrich_finding_updates_model_immutably(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Ensure enrich_finding populates ai_enrichment on a new Finding without mutating original."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_response = MagicMock()
        mock_response.text = "### Executive Summary\nSummary\n\n### Root Cause Analysis\nRCA\n\n### Remediation Playbook\nRemediation"
        mock_client.models.generate_content.return_value = mock_response

        enricher = GeminiEnricher(api_key="mock_test_key")
        enriched_finding = enricher.enrich_finding(
            self.finding, log_event=self.log_event, risk_score=90
        )

        # Original finding must remain untouched
        self.assertIsNone(self.finding.ai_enrichment)

        # New finding must carry enrichment
        self.assertIsNotNone(enriched_finding.ai_enrichment)
        assert enriched_finding.ai_enrichment is not None
        self.assertIn("Executive Summary", enriched_finding.ai_enrichment)
        self.assertEqual(enriched_finding.rule_id, self.finding.rule_id)

    # -------------------------------------------------------------------------
    # 3. Graceful Fallback Tests (Missing Key, Quota, Exceptions)
    # -------------------------------------------------------------------------

    def test_fallback_when_api_key_is_missing(self) -> None:
        """Ensure enricher degrades gracefully to deterministic analysis when no API key exists."""
        with patch.dict(os.environ, {}, clear=True):
            enricher = GeminiEnricher(api_key=None)
            result = enricher.enrich(
                self.finding, log_event=self.log_event, risk_score=90
            )

            self.assertTrue(result.is_fallback)
            self.assertIsNotNone(result.error_message)
            self.assertIn(
                "Automated detection flagged a HIGH severity SQL_INJECTION",
                result.executive_summary,
            )
            self.assertIn("UNION SELECT", result.root_cause_analysis)
            self.assertIn("Triage", result.remediation_playbook)

    @patch("soc_analyst.ai.enricher.genai.Client")
    def test_fallback_on_api_error_or_quota_exhausted(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Ensure APIError (e.g. HTTP 429 Quota Exceeded) triggers fallback without crashing."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        # Simulate APIError / ResourceExhausted
        mock_client.models.generate_content.side_effect = errors.APIError(
            429,
            {"error": {"code": 429, "message": "Resource exhausted / quota exceeded"}},
        )

        enricher = GeminiEnricher(api_key="mock_test_key")
        result = enricher.enrich(
            self.finding, log_event=self.log_event, risk_score=90
        )

        self.assertTrue(result.is_fallback)
        self.assertIsNotNone(result.error_message)
        self.assertIn("API Error", result.error_message or "")
        self.assertIn(
            "Automated detection flagged a HIGH severity",
            result.executive_summary,
        )

    @patch("soc_analyst.ai.enricher.genai.Client")
    def test_fallback_on_network_timeout(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Ensure network timeouts or connection drops trigger deterministic fallback."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        # Simulate network timeout
        mock_client.models.generate_content.side_effect = TimeoutError(
            "Connection timed out."
        )

        enricher = GeminiEnricher(api_key="mock_test_key")
        result = enricher.enrich(
            self.finding, log_event=self.log_event, risk_score=90
        )

        self.assertTrue(result.is_fallback)
        self.assertIn("TimeoutError", result.error_message or "")
        self.assertIn("Remediation Playbook", result.raw_response)

    @patch("soc_analyst.ai.enricher.genai.Client")
    def test_module_level_enrich_finding_convenience(
        self, mock_client_cls: MagicMock
    ) -> None:
        """Verify module-level enrich_finding function properly orchestrates enrichment."""
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client

        mock_response = MagicMock()
        mock_response.text = "### Executive Summary\nModule test\n\n### Root Cause Analysis\nDetails\n\n### Remediation Playbook\nSteps"
        mock_client.models.generate_content.return_value = mock_response

        enriched = enrich_finding(
            self.finding,
            log_event=self.log_event,
            risk_score=90,
            api_key="mock_key",
        )

        self.assertIsNotNone(enriched.ai_enrichment)
        assert enriched.ai_enrichment is not None
        self.assertIn("Module test", enriched.ai_enrichment)


if __name__ == "__main__":
    unittest.main()
