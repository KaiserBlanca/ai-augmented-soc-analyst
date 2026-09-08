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
- **Next Recommended Task:**
  - Implement log parsers (e.g., `parsers/apache.py`, `parsers/nginx.py`) outputting normalized `LogEvent` objects.