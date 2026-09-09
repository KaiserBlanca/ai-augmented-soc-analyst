# AI-Augmented SOC Analyst — Development Log

## Purpose
This file is the persistent development memory for AI-assisted coding sessions.

## Decision Registry
### ADR-001 — Deterministic Detection Before AI
- **Status:** Accepted
- **Date:** 2026-09-09
- **Decision:** Threat detection will be performed locally using deterministic logic (Regex, rules). Gemini will only enrich findings after local detection.
- **Reason:** Core security functionality must remain explainable, testable, and usable offline.

### ADR-002 — Minimal Dependency Policy
- **Status:** Accepted
- **Date:** 2026-09-09
- **Decision:** Use Python standard-library whenever practical. Allowed extra dependencies: `rich`, `google-genai`, `python-dotenv`, `pytest`.
- **Reason:** Keeps project lightweight, maintainable, and portfolio-friendly.

### ADR-003 — Graceful Degradation in Log Parsers
- **Status:** Accepted
- **Date:** 2026-09-09
- **Decision:** Log parsers must never terminate execution on malformed lines, missing fields, or corrupted timestamps. They must log diagnostic warnings and return None or partially populated LogEvent instances without raising uncaught exceptions. File readers must use replacement decoding to survive binary/corrupted bytes.
- **Reason:** SOC analysts analyze massive, heterogeneous log streams. Ingestion pipelines must be resilient against corrupted telemetry and adversarial obfuscation attempts.

### ADR-004 — Explainable Deterministic Detection Architecture
- **Status:** Accepted
- **Date:** 2026-09-09
- **Decision:** All detection engines must inherit from `BaseDetector`, operate deterministically without AI dependencies, and utilize named, documented regex patterns with explicit confidence levels. Each generated `Finding` must include explicit forensic evidence, technical impact, and business risk explanations. Detection logic must evaluate canonical (URL-decoded) inputs to mitigate obfuscation.
- **Reason:** Satisfies core portfolio principles: explainability, offline testability, deterministic detection before AI enrichment, and executive-ready risk communication.

### ADR-005 — Dynamic Contextual Risk Scoring Engine
- **Status:** Accepted
- **Date:** 2026-09-09
- **Decision:** Risk scores are computed deterministically on a 0-100 scale using three transparent dimensions: Inherent Threat Severity (0-50 pts), Detection Confidence (0-30 pts), and HTTP Response Outcome (0-20 pts). Successful server responses (HTTP 200) escalate risk heavily (+20), server crashes/errors add +15, while client/boundary blocks (403/401) add +5, and non-existent targets (404) add 0 pts.
- **Reason:** Reflects real-world SOC triage priorities where executed payloads on live endpoints require urgent response, while blocked/failed attempts on non-existent routes represent lower operational threat.

### ADR-006 — Gemini AI Threat Enrichment Architecture & Graceful Fallback
- **Status:** Accepted
- **Date:** 2026-09-09
- **Decision:** High-risk findings are enriched using Google Gemini (`gemini-2.5-flash` via official `google-genai` SDK) strictly after local detection and scoring. Structured prompts enforce data-minimization (no raw log dumps or private tokens). AI responses produce Executive Summary, Root Cause Analysis, and Remediation Playbook. In the event of missing keys, quota depletion, or network drops, a deterministic fallback analysis is generated without raising exceptions.
- **Reason:** Ensures the tool is robust, privacy-conscious, and compliant with portfolio and security standards (Rules 9, 10, 11, 12, 23).

---

## Session History

### 2026-09-09 — Session 01: Project Scaffolding & Initial Setup
- **Session Goal:** Initialize repository structure and establish development standards.
- **Work Completed:**
  - Initialized root project structure (`.ai/`, `samples/`, `tests/`, `src/soc_analyst/`).
  - Created `.ai/CONTEXT.md`, `.ai/RULES.md`, and `.ai/LOGS.md`.
- **Files Created:**
  - `.ai/CONTEXT.md`
  - `.ai/RULES.md`
  - `.ai/LOGS.md`
- **Current Project State:**
  - Project development standards are defined.
  - Deterministic detection is established as the baseline.
  - No Python code written yet.
- **Next Recommended Task:**
  1. Implement `LogEvent` and `Finding` models in `src/soc_analyst/models/`.

### 2026-09-09 — Session 02: Core Data Models (LogEvent & Finding)
- **Session Goal:** Implement immutable models for log telemetry and security findings.
- **Work Completed:**
  - Created `LogEvent` frozen dataclass for normalized, immutable log records across parsers.
  - Implemented `Finding` frozen dataclass along with `Severity` and `Confidence` Str-Enums.
  - Enforced strict type-hinting and comprehensive docstrings explaining security vs business impact and severity vs confidence.
  - Created unit test suite in `tests/test_models.py` verifying immutability and model contracts.
- **Files Created:**
  - `src/soc_analyst/models/log_event.py`
  - `src/soc_analyst/models/finding.py`
  - `src/soc_analyst/models/__init__.py`
  - `src/soc_analyst/__init__.py`
  - `tests/test_models.py`
- **Tests Performed:**
  - Ran `python -m unittest discover tests` (4 tests passed).
- **Known Limitations:**
  - Parsers and detection engines have not yet been wired up.
  - Next Recommended Task:
  - Implement log parsers (e.g., `parsers/apache.py`, `parsers/nginx.py`) outputting normalized `LogEvent` objects.

### 2026-09-09 — Session 03: Apache Log Parser & Graceful Degradation
- **Session Goal:** Implement robust regex-based parser for Apache Common and Combined log formats with defensive error handling and comprehensive pytest suite.
- **Work Completed:**
  - Created `src/soc_analyst/parsers/apache.py` with `APACHE_COMBINED_PATTERN` and `APACHE_COMMON_PATTERN` regexes.
  - Implemented `ApacheLogParser` class and module-level helpers (`parse_line`, `parse_lines`, `parse_file`).
  - Added defensive helpers: `_parse_timestamp`, `_parse_request_field`, and `_parse_status_code` to guarantee graceful degradation.
  - Created `src/soc_analyst/parsers/__init__.py` exposing clean parser interfaces.
  - Configured `pyproject.toml` with `pytest.ini_options` setting `pythonpath = ["src"]`.
  - Created `tests/test_apache_parser.py` testing 18 test cases covering valid Combined and Common formats, IPv6, security payloads (SQLi, XSS, Path Traversal), truncated lines, corrupted timestamps, non-numeric status codes, and file error handling.
- **Files Created/Modified:**
  - `src/soc_analyst/parsers/apache.py` (created)
  - `src/soc_analyst/parsers/__init__.py` (created)
  - `tests/test_apache_parser.py` (created)
  - `pyproject.toml` (created)
  - `.gitignore` (updated)
  - `.ai/LOGS.md` (updated)
- **Tests Performed:**
  - Ran `pytest -v` (22 passed in 0.03s: 18 parser tests, 4 model tests).
- **Known Limitations:**
  - Nginx and Linux Auth (`/var/log/auth.log`) parsers not yet implemented.
  - Detection rules (SQLi, XSS, Brute Force) not yet implemented.
- **Next Recommended Task:**
  - Implement deterministic detection rules starting with SQL Injection detector (`detection/sqli.py`) consuming `LogEvent`.

### 2026-09-09 — Session 04: Detection Engine Core, SQLi & XSS Detectors
- **Session Goal:** Establish deterministic detection framework with `BaseDetector`, implement `SQLInjectionDetector` and `XSSDetector` with explainable evidence, technical impact, and business risk, and create pytest suites testing both attack and benign requests.
- **Work Completed:**
  - Created abstract base class `BaseDetector` in `src/soc_analyst/detection/base.py` defining common interface (`detect`, `detect_all`, `rule_id`, `attack_type`, `name`).
  - Implemented `SQLInjectionDetector` in `src/soc_analyst/detection/sqli.py` with 5 prioritized, named regex patterns (UNION SELECT, Time-based blind, Stacked queries, Boolean tautologies, Comment truncation). Handles URL-decoded payloads.
  - Implemented `XSSDetector` in `src/soc_analyst/detection/xss.py` with 6 named regex patterns (<script> tags, javascript/data pseudo-protocols, dangerous HTML elements, inline DOM event handlers, popups/eval). Handles URL-decoded payloads.
  - Structured all generated `Finding` objects with forensic evidence, technical impact, and business risk according to Rules 7, 8, 14, and 28.
  - Created `src/soc_analyst/detection/__init__.py` exporting detectors and base contract.
  - Implemented `tests/test_sqli_detector.py` (16 test cases) and `tests/test_xss_detector.py` (14 test cases) covering attack vectors, case-insensitivity, URL-encoded inputs, and negative benign traffic tests.
- **Files Created/Modified:**
  - `src/soc_analyst/detection/base.py` (created)
  - `src/soc_analyst/detection/sqli.py` (created)
  - `src/soc_analyst/detection/xss.py` (created)
  - `src/soc_analyst/detection/__init__.py` (created)
  - `tests/test_sqli_detector.py` (created)
  - `tests/test_xss_detector.py` (created)
  - `.ai/LOGS.md` (updated)
- **Tests Performed:**
  - Ran `pytest -v` (52 passed in 0.07s: 16 SQLi tests, 14 XSS tests, 18 parser tests, 4 model tests).
- **Known Limitations:**
  - Brute force detector (stateful / aggregation-based) not yet implemented.
  - CLI runner orchestrating parser -> detectors not yet implemented.
- **Next Recommended Task:**
  - Implement stateful Brute Force detector (`detection/brute_force.py`) tracking failed authentication attempts across time windows.

### 2026-09-09 — Session 05: Dynamic Risk Evaluator Engine
- **Session Goal:** Implement `src/soc_analyst/risk/evaluator.py` to calculate transparent, 0-100 dynamic risk scores evaluating finding severity, confidence, and contextual HTTP status codes (200 OK vs 403 vs 404).
- **Work Completed:**
  - Created `RiskAssessment` frozen dataclass and `RiskEvaluator` class in `src/soc_analyst/risk/evaluator.py`.
  - Implemented 3-factor scoring formula:
    - Inherent Severity: CRITICAL (50 pts), HIGH (40 pts), MEDIUM (25 pts), LOW (10 pts).
    - Detection Confidence: HIGH (30 pts), MEDIUM (20 pts), LOW (10 pts).
    - HTTP Status Outcome: 2xx (+20 pts), 5xx (+15 pts), 3xx (+10 pts), 401/403 (+5 pts), 404 (0 pts), Neutral/Unknown (+5 pts).
  - Implemented `calculate_score`, `evaluate`, and `evaluate_all` (with descending risk score sorting).
  - Created `src/soc_analyst/risk/__init__.py` exposing evaluator models and functions.
  - Created comprehensive test suite in `tests/test_risk_evaluator.py` (10 test cases) verifying status code sensitivity (200 > 500 > 403 > 404), severity ordering, confidence ordering, boundary clamping (0-100), and immutability.
- **Files Created/Modified:**
  - `src/soc_analyst/risk/evaluator.py` (created)
  - `src/soc_analyst/risk/__init__.py` (created)
  - `tests/test_risk_evaluator.py` (created)
  - `.ai/LOGS.md` (updated)
- **Tests Performed:**
  - Ran `pytest -v` (62 passed in 0.08s: 10 Risk Evaluator tests, 16 SQLi tests, 14 XSS tests, 18 parser tests, 4 model tests).
- **Known Limitations:**
  - Gemini AI enrichment layer and Rich reporting CLI not yet connected to RiskEvaluator.
- **Next Recommended Task:**
  - Implement Brute Force detector (`detection/brute_force.py`) or wire detection + risk evaluation pipeline into CLI.

### 2026-09-09 — Session 06: Gemini AI Threat Enrichment & Graceful Fallback
- **Session Goal:** Implement `src/soc_analyst/ai/enricher.py` utilizing official `google-genai` SDK and `gemini-2.5-flash` model, read `GEMINI_API_KEY` via `python-dotenv`, craft data-minimized structured prompt, generate 3-part SOC analysis (Executive Summary, Root Cause Analysis, Remediation Playbook), and provide deterministic local fallback on missing key or API quota errors with mocked unit tests.
- **Work Completed:**
  - Installed `google-genai` (v2.22.0) and `python-dotenv` (v1.2.3).
  - Created `src/soc_analyst/ai/enricher.py` containing `GeminiEnricher` and `EnrichmentResult`.
  - Formulated structured prompt with telemetry data minimization (no bulk raw logs or private tokens).
  - Engineered 3-part SOC analysis response parser (`_parse_ai_response`) and deterministic fallback generator (`_generate_fallback_enrichment`).
  - Added robust exception handling for `google.genai.errors.APIError` (e.g. 429 quota exhaustion), network timeouts, and missing credentials without crashing the pipeline.
  - Implemented `enrich_finding` to immutably populate `finding.ai_enrichment`.
  - Created `src/soc_analyst/ai/__init__.py` and `.env.example`.
  - Created `tests/test_ai_enricher.py` (9 test cases) using `unittest.mock` for offline testing of successful responses, prompt construction, section parsing, missing API key fallback, quota errors, and network timeouts.
- **Files Created/Modified:**
  - `src/soc_analyst/ai/enricher.py` (created)
  - `src/soc_analyst/ai/__init__.py` (created)
  - `tests/test_ai_enricher.py` (created)
  - `.env.example` (created)
  - `.ai/LOGS.md` (updated)
- **Tests Performed:**
  - Ran `pytest -v` (71 passed in 0.36s: 9 AI enricher tests, 10 Risk evaluator tests, 16 SQLi tests, 14 XSS tests, 18 parser tests, 4 model tests).
- **Known Limitations:**
  - Stateful Brute Force detector not yet implemented.
  - CLI runner not yet implemented to connect all components into a user command.
- **Next Recommended Task:**
  - Implement stateful Brute Force detector (`detection/brute_force.py`) or implement end-to-end CLI orchestrator (`cli.py`).