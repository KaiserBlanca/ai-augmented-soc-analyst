````markdown
# AI-Augmented SOC Analyst — Project Context

## 1. Project Identity

**Project Name:** AI-Augmented SOC Analyst  
**Project Type:** Python CLI Cybersecurity Tool  
**Primary Domain:** SOC Operations / Log Analysis / Threat Detection / Cyber Risk Analysis  
**Primary Goal:** Detect suspicious activities in server logs using deterministic detection rules and enrich the findings with AI-assisted security and business risk analysis.

This project is designed primarily as a portfolio-grade cybersecurity project demonstrating:

- Python software engineering
- Security log analysis
- Detection engineering
- Regex-based threat detection
- SOC analyst workflows
- Risk assessment
- Responsible use of Large Language Models in cybersecurity
- Secure API integration
- CLI application design
- Business-oriented cyber risk communication

---

# 2. Core Problem

Web servers and Linux systems generate large amounts of log data.

Manual inspection of these logs is:

- slow,
- repetitive,
- error-prone,
- difficult to prioritize.

This project analyzes log records and attempts to identify suspicious behavior such as:

- SQL Injection attempts
- Cross-Site Scripting attempts
- Brute-force activity
- Suspicious HTTP requests
- Repeated authentication failures
- Potential reconnaissance activity

The system then converts technical detections into understandable security and business risk information.

---

# 3. High-Level Processing Flow

The intended processing pipeline is:

```text
Log File
   |
   v
Log Parser
   |
   v
Detection Engine
   |
   +---- SQL Injection Detector
   |
   +---- XSS Detector
   |
   +---- Brute Force Detector
   |
   +---- Future Detection Rules
   |
   v
Detection / Finding Objects
   |
   v
Risk Evaluation
   |
   +---- Local deterministic scoring
   |
   +---- Gemini AI enrichment
   |
   v
CLI Report
````

The AI component MUST NOT replace deterministic detection logic.

Detection should first occur locally using explicit, auditable rules.

Gemini is used as an **analysis/enrichment layer**, not as the primary detection engine.

---

# 4. Architectural Principles

The application should follow a modular architecture.

Suggested structure:

```text
ai-augmented-soc-analyst/
|
├── .ai/
│   ├── CONTEXT.md
│   ├── RULES.md
│   └── LOGS.md
|
├── src/
│   └── soc_analyst/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       |
│       ├── parsers/
│       │   ├── __init__.py
│       │   ├── apache.py
│       │   ├── nginx.py
│       │   └── linux_auth.py
│       |
│       ├── detection/
│       │   ├── __init__.py
│       │   ├── base.py
│       │   ├── sqli.py
│       │   ├── xss.py
│       │   └── brute_force.py
│       |
│       ├── models/
│       │   ├── __init__.py
│       │   ├── log_event.py
│       │   └── finding.py
│       |
│       ├── risk/
│       │   ├── __init__.py
│       │   ├── scorer.py
│       │   └── business_risk.py
│       |
│       ├── ai/
│       │   ├── __init__.py
│       │   └── gemini_client.py
│       |
│       └── reporting/
│           ├── __init__.py
│           └── console.py
|
├── tests/
|
├── samples/
|
├── .env.example
├── .gitignore
├── pyproject.toml
└── README.md
```

This structure is a target architecture and may evolve.

Changes to major architectural decisions should be recorded in `.ai/LOGS.md`.

---

# 5. Separation of Responsibilities

## Log Parsers

Responsibilities:

* Read supported log formats.
* Convert raw log lines into structured Python objects.
* Avoid performing security decisions inside parsers.
* Handle malformed lines gracefully.

Example output:

```text
LogEvent
- timestamp
- source_ip
- method
- path
- status_code
- user_agent
- raw_line
```

---

## Detection Engine

Responsibilities:

* Analyze structured log events.
* Apply deterministic detection rules.
* Detect known suspicious patterns.
* Generate structured security findings.

Initial detection categories:

```text
SQL_INJECTION
XSS
BRUTE_FORCE
```

Future categories may include:

```text
PATH_TRAVERSAL
COMMAND_INJECTION
SCANNER_ACTIVITY
SUSPICIOUS_USER_AGENT
CREDENTIAL_STUFFING
```

Detectors should be independently testable.

---

# 6. Regex Usage

Regular expressions are used for lightweight detection of suspicious payload patterns.

Regex MUST NOT be treated as a perfect IDS/IPS engine.

Regex rules should prioritize:

* readability,
* maintainability,
* explainability,
* low false-positive rates.

Every important detection pattern should be accompanied by:

* explanation,
* detection rationale,
* example malicious input,
* example benign input where relevant,
* tests.

Complex one-line regex expressions should be avoided where simpler detection logic is possible.

---

# 7. Risk Scoring

Each finding should contain a local risk assessment before AI enrichment.

Suggested risk dimensions:

```text
severity
confidence
technical_impact
business_impact
```

Example severity values:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

Risk scoring should remain deterministic whenever possible.

The system should distinguish:

**Severity**

> How damaging the attack could be.

**Confidence**

> How certain the system is that the event is malicious.

These concepts MUST NOT be treated as the same metric.

---

# 8. Business Risk Perspective

One of the differentiating features of this project is that technical security findings should be translated into business impact.

Security findings should attempt to answer:

* What system could be affected?
* What could an attacker achieve?
* Could confidentiality be impacted?
* Could integrity be impacted?
* Could availability be impacted?
* Could credentials or customer data be exposed?
* Could the event cause operational disruption?
* Could it create financial or regulatory exposure?

Example:

```text
Technical Finding:
Possible SQL Injection attempt.

Technical Impact:
An attacker may attempt unauthorized database access.

Business Risk:
If successful, the attack may expose customer information,
cause regulatory consequences, damage customer trust,
and require incident response activities.
```

Business risk descriptions must remain proportional to the evidence.

Do not claim a successful compromise when only an attack attempt was detected.

---

# 9. Gemini AI Integration

Google Gemini API is used only after local detection.

Gemini may assist with:

* interpreting findings,
* explaining attack techniques,
* generating SOC analyst summaries,
* describing potential impact,
* suggesting defensive actions,
* translating technical findings into business risk language.

Gemini MUST NOT be considered a trusted source of truth.

AI output must be treated as:

```text
Analyst Assistance
```

not:

```text
Definitive Security Verdict
```

Where practical, Gemini should receive structured finding data rather than arbitrary full log files.

---

# 10. Sensitive Data Handling

Before sending information to an external AI API, consider whether the input contains:

* passwords,
* tokens,
* session identifiers,
* API keys,
* personally identifiable information,
* internal hostnames,
* sensitive URLs,
* customer data.

Sensitive information should be masked, minimized, or excluded whenever possible.

The project should prefer sending only the minimum context necessary for risk analysis.

---

# 11. CLI Interface

The application is primarily a command-line tool.

Example conceptual usage:

```bash
python -m soc_analyst analyze samples/access.log
```

Future interface:

```bash
soc-analyst analyze access.log
```

Possible CLI options:

```text
--format apache
--format nginx
--format linux-auth

--ai
--no-ai

--severity HIGH
--output report.json
```

The CLI should remain simple and predictable.

---

# 12. Rich Terminal UI

The `rich` Python library may be used for terminal presentation.

Potential uses:

* tables,
* severity indicators,
* progress information,
* formatted findings,
* summary panels.

Rich is a presentation dependency.

Security logic MUST NOT depend on Rich.

Core detection functionality should remain usable independently from terminal presentation.

---

# 13. Technology Stack

Primary technologies:

## Language

```text
Python 3.11+
```

Prefer modern Python features when they improve readability.

---

## Core Python Modules

Prefer the standard library whenever practical.

Likely modules:

```text
re
pathlib
dataclasses
enum
collections
datetime
json
logging
typing
```

---

## External Libraries

External dependencies should remain minimal.

Expected dependencies may include:

```text
rich
google-genai
python-dotenv
```

Testing:

```text
pytest
```

Do NOT introduce large frameworks without clear justification.

---

# 14. Configuration

Secrets MUST NOT be hard-coded.

Gemini credentials should be provided through environment variables.

Example:

```text
GEMINI_API_KEY
```

A `.env.example` may document required variables.

Actual `.env` files and API keys MUST be excluded from Git.

---

# 15. Target Audience

Primary audiences:

## SOC / Cybersecurity Recruiters

The project should demonstrate practical security reasoning rather than only Python syntax.

## Junior SOC Analysts

The tool should provide understandable explanations for suspicious activity.

## Security-Conscious Developers

The codebase should demonstrate clean detection logic and secure software practices.

## Technical Hiring Managers

The architecture should demonstrate:

* modularity,
* testability,
* maintainability,
* security awareness,
* engineering discipline.

---

# 16. Portfolio Objective

This project is not intended to pretend to be a production SIEM replacement.

It should instead demonstrate the ability to combine:

```text
Cybersecurity
+
Python
+
Detection Engineering
+
AI
+
Risk Analysis
+
Business Context
```

The project's strongest portfolio value should come from explainability and engineering quality.

---

# 17. AI Agent Role

The coding AI/agent acts as:

```text
Senior Python Engineer
+
Security Software Architect
+
Detection Engineering Assistant
+
Context-Aware Pair Programmer
```

The agent should help with:

* architecture,
* implementation,
* refactoring,
* tests,
* security reasoning,
* documentation,
* debugging,
* threat detection logic.

The agent MUST follow `.ai/RULES.md`.

---

# 18. AI Agent Priorities

When making decisions, prioritize in this order:

1. Correctness
2. Security
3. Explainability
4. Maintainability
5. Testability
6. Simplicity
7. Performance
8. Convenience

Do not sacrifice clarity for clever code.

---

# 19. Definition of a Good Feature

A feature is not complete merely because the code runs.

A good feature should ideally include:

```text
Implementation
+
Type Hints
+
Docstrings
+
Error Handling
+
Security Explanation
+
Business Risk Explanation
+
Tests
```

---

# 20. Current Scope

Initial MVP:

```text
1. Read a web server log file.
2. Parse log records.
3. Detect SQL Injection patterns.
4. Detect XSS patterns.
5. Detect brute-force behavior.
6. Generate structured findings.
7. Assign local severity/confidence.
8. Display findings using Rich.
9. Optionally enrich findings using Gemini.
10. Produce a concise risk summary.
```

Features outside this scope should not be introduced unless they clearly support the MVP or are explicitly requested.

---

# 21. Non-Goals

The MVP is NOT intended to become:

* a SIEM platform,
* an endpoint protection product,
* an autonomous incident-response platform,
* a vulnerability scanner,
* an exploit framework,
* a full IDS/IPS replacement,
* a distributed log processing platform,
* a machine-learning training pipeline.

Avoid unnecessary scope expansion.

---

# 22. Source of Truth

For AI-assisted development, use the following priority:

```text
1. Current explicit user instruction
2. .ai/RULES.md
3. .ai/CONTEXT.md
4. Existing codebase and tests
5. .ai/LOGS.md architectural decisions
6. AI assumptions
```

If the codebase and documentation conflict, identify the conflict explicitly rather than silently choosing one interpretation.

````

### `.ai/RULES.md`

```markdown
# AI-Augmented SOC Analyst — AI Agent Rules

# 1. Purpose

This document contains mandatory rules for any AI coding agent working on this repository.

These rules apply to:

- Antigravity
- Agentic IDE tools
- AI coding assistants
- Autonomous coding agents
- Chat-based development assistants

The agent MUST read this file before making architectural or implementation decisions.

Keywords:

```text
MUST     = mandatory
MUST NOT = prohibited
SHOULD   = strong recommendation
MAY      = optional
````

---

# 2. Core Principle

The project must remain:

```text
Simple
Secure
Explainable
Modular
Testable
Portfolio-Ready
```

Do not introduce complexity simply because it is technically possible.

---

# 3. Do Not Overengineer

The agent MUST prefer the simplest implementation that correctly satisfies the requirement.

The agent MUST NOT introduce unnecessary:

* abstractions,
* service layers,
* factories,
* dependency injection frameworks,
* plugin systems,
* message queues,
* databases,
* web frameworks,
* asynchronous architectures,
* microservices,
* containers,
* orchestration systems.

Unless the current requirement clearly needs them.

Before introducing a major abstraction, ask:

```text
What current problem does this solve?
```

If there is no concrete answer, do not add it.

---

# 4. Dependency Policy

Adding unnecessary or heavy dependencies is PROHIBITED.

Prefer:

```text
Python Standard Library
```

over third-party libraries whenever the standard library can solve the problem cleanly.

Allowed dependencies should have a concrete purpose.

Examples of reasonable dependencies:

```text
rich
google-genai
python-dotenv
pytest
```

A new dependency MUST NOT be introduced merely to avoid writing a few lines of straightforward Python.

Before adding a dependency, the agent MUST explain:

```text
1. Why the dependency is required.
2. Why the standard library is insufficient.
3. What security/maintenance cost it introduces.
```

Never silently modify dependencies.

---

# 5. Type Hinting Is Mandatory

All production functions and methods MUST use type hints.

Bad:

```python
def analyze(log):
    ...
```

Good:

```python
def analyze(log: str) -> list[str]:
    ...
```

Complex return structures SHOULD use:

* dataclasses,
* TypedDict where appropriate,
* enums,
* explicit model classes.

Avoid meaningless types such as:

```python
Any
dict
list
```

when a more precise type is practical.

---

# 6. Docstrings Are Mandatory

Public:

* classes,
* functions,
* methods,
* modules with non-obvious responsibilities

MUST include useful docstrings.

Docstrings should explain:

```text
What the component does.
Important arguments.
Return value.
Important exceptions.
Security implications when relevant.
```

Do NOT write useless docstrings.

Bad:

```python
def detect_attack(event: LogEvent) -> bool:
    """Detect attack."""
```

Better:

```python
def detect_attack(event: LogEvent) -> bool:
    """Return whether a parsed log event matches known attack indicators.

    The function performs deterministic local analysis only and does not
    contact external AI services.
    """
```

---

# 7. Security Logic Must Be Explained

Whenever implementing or modifying detection logic, the agent MUST explain:

```text
1. What security behavior is being detected.
2. Why the behavior can indicate an attack.
3. What assumptions the rule makes.
4. Likely false positives.
5. Likely false negatives.
6. How an analyst should interpret the result.
```

A regex is NOT self-explanatory.

Do not provide a security regex without explaining its detection rationale.

---

# 8. Business Risk Must Be Explained

Security findings MUST be connected to potential business impact where appropriate.

For meaningful security functionality, explain both:

```text
Technical Security Impact
```

and:

```text
Business Risk
```

Possible business impact categories:

* customer data exposure,
* authentication compromise,
* service disruption,
* financial loss,
* regulatory exposure,
* incident response cost,
* reputational damage,
* operational interruption.

Do not exaggerate.

A detected attack attempt does NOT prove compromise.

Use language such as:

```text
may
could
potential
suspected
attempt
possible
```

unless evidence supports a stronger conclusion.

---

# 9. Separate Detection From AI Analysis

Gemini MUST NOT be the primary security detection mechanism.

Required architecture:

```text
Raw Log
   ↓
Parser
   ↓
Deterministic Detection
   ↓
Structured Finding
   ↓
Optional AI Enrichment
```

Do NOT send every raw log line to Gemini and ask:

```text
"Is this malicious?"
```

The system should be able to detect supported threats without Gemini.

AI should enrich, summarize, contextualize, or prioritize findings.

---

# 10. Treat AI Output as Untrusted

Output received from Gemini MUST be treated as untrusted external data.

The agent MUST NOT assume Gemini output is:

* factually correct,
* valid JSON,
* safe,
* complete,
* consistent,
* authoritative.

AI responses MUST be validated before being used programmatically.

Where structured output is expected, implement defensive parsing.

Failures should degrade gracefully.

Example expected behavior:

```text
Local detection succeeds.
Gemini request fails.
CLI still displays the local finding.
```

An AI API failure MUST NOT break the core detection workflow.

---

# 11. Protect Secrets

NEVER hard-code:

* API keys,
* passwords,
* tokens,
* credentials.

Expected configuration:

```text
GEMINI_API_KEY
```

Secrets MUST be read from environment variables or another appropriate configuration mechanism.

`.env` MUST remain excluded from version control.

Provide `.env.example` instead when documentation is needed.

---

# 12. Minimize Data Sent to Gemini

Do NOT send unnecessary raw log data to Gemini.

Before transmitting data to an external API, consider whether it contains:

* IP addresses,
* usernames,
* session IDs,
* authorization headers,
* cookies,
* query parameters,
* passwords,
* tokens,
* customer information,
* internal hostnames.

Prefer structured and minimized input such as:

```json
{
  "attack_type": "SQL_INJECTION",
  "severity": "HIGH",
  "http_method": "GET",
  "suspicious_fragment": "' OR 1=1 --",
  "status_code": 403
}
```

instead of transmitting entire files.

---

# 13. Regex Rules Must Stay Understandable

Regex patterns MUST prioritize readability.

Do not create extremely large "magic regex" expressions if the same detection can be implemented more clearly using multiple checks.

Patterns SHOULD be:

* named,
* documented,
* independently testable.

Example:

```python
SQLI_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(...),
    re.compile(...),
)
```

rather than embedding unexplained expressions directly inside business logic.

---

# 14. Do Not Confuse Severity and Confidence

Every detection design must recognize the difference between:

```text
Severity = potential damage if the threat is real.
Confidence = certainty that the event is malicious.
```

Example:

```text
Potential SQL Injection
Severity: HIGH
Confidence: MEDIUM
```

This is valid.

Do NOT automatically assign CRITICAL severity simply because a regex matched.

---

# 15. Avoid Security Theater

Do not add features merely because they sound cybersecurity-related.

Examples:

* meaningless "AI threat score,"
* fake CVSS calculations without required metrics,
* random threat intelligence terminology,
* arbitrary confidence percentages,
* claiming zero-day detection,
* claiming production-grade SOC capability.

Every metric must have a defensible methodology.

---

# 16. Do Not Invent Library APIs

If unsure whether a library function, method, parameter, or API exists:

DO NOT GUESS.

The agent MUST explicitly state:

```text
"Emin değilim; bu API/fonksiyon sürüme bağlı olabilir. Dokümantasyonu doğrulamamız gerekiyor."
```

or equivalent wording.

The agent should then verify using available documentation/tools when possible.

Inventing plausible-looking library APIs is prohibited.

This rule is especially important for:

* Google Gemini SDK
* Rich
* Typer/Click if introduced
* third-party security libraries
* changing Python APIs

---

# 17. Version Awareness

Third-party APIs can change.

Before relying on version-sensitive behavior, check:

* installed dependency version,
* project dependency declaration,
* official documentation when available.

Do not mix examples from different Gemini SDK generations.

---

# 18. Code Must Be Delivered in Understandable Pieces

When explaining a significant implementation, do NOT dump hundreds of lines of code without structure.

Prefer this order:

```text
1. Goal
2. File being changed
3. Small coherent code block
4. Security reasoning
5. Business-risk reasoning
6. Test or verification step
```

Each code block should have one clear responsibility.

For direct repository edits by an autonomous agent, complete files may be written when necessary, but the explanation should still identify the significant changes separately.

---

# 19. Do Not Rewrite Unrelated Code

When asked to modify one feature:

MUST NOT unnecessarily:

* rename unrelated classes,
* move unrelated modules,
* reformat the entire project,
* replace working architecture,
* change public APIs.

Keep diffs focused.

Refactoring unrelated code requires an explicit reason.

---

# 20. Inspect Before Editing

Before modifying existing code, inspect:

```text
1. Relevant files.
2. Related tests.
3. Existing models/interfaces.
4. Dependency configuration.
5. .ai/CONTEXT.md
6. Relevant decisions in .ai/LOGS.md
```

Do not assume the repository state.

---

# 21. Preserve Existing Decisions

Architectural decisions recorded in `.ai/LOGS.md` SHOULD be treated as active decisions unless:

* the user explicitly changes them,
* implementation evidence proves they are obsolete,
* a security/correctness issue requires reconsideration.

If changing an existing architectural decision, explain why.

Then record the new decision in `.ai/LOGS.md`.

---

# 22. Testing Is Required for Detection Logic

New detection rules MUST include tests.

At minimum test:

```text
1. Clearly malicious example.
2. Clearly benign example.
3. Relevant edge case.
```

Regex detection tests SHOULD explicitly test false positives.

Example:

```text
Attack:
?id=1' OR 1=1--

Benign:
?q=selecting+best+product
```

A detector is incomplete without reasonable negative tests.

---

# 23. Prefer Deterministic Tests

Tests MUST NOT require live Gemini API access by default.

Gemini interactions should be:

* mocked,
* abstracted,
* disabled during normal unit tests.

Core test suite should run offline.

Live API tests, if any, must be explicitly separated.

---

# 24. Error Handling

Expected operational failures MUST be handled gracefully.

Examples:

* missing file,
* unreadable file,
* unsupported log format,
* malformed log line,
* missing Gemini API key,
* Gemini timeout,
* invalid Gemini response,
* network failure.

Do not use:

```python
except Exception:
    pass
```

Do not silently swallow errors.

Catch specific exceptions when practical.

---

# 25. Logging

Application diagnostics should use Python's `logging` module where appropriate.

Do not use scattered `print()` calls for internal debugging.

User-facing terminal output may use Rich.

Separate:

```text
Application diagnostics
```

from:

```text
CLI presentation
```

---

# 26. Maintain Layer Boundaries

Parsers MUST NOT:

* call Gemini,
* calculate business risk,
* render Rich output.

Detectors MUST NOT:

* print directly to the terminal,
* depend on Rich,
* manage API keys.

AI integration MUST NOT:

* parse files,
* implement primary detection logic.

Reporting MUST NOT:

* decide whether an event is malicious.

Maintain separation of concerns.

---

# 27. Models Should Be Structured

Do not pass important security information through loosely structured dictionaries when a dedicated model provides clearer semantics.

Prefer:

```python
@dataclass(frozen=True)
class Finding:
    ...
```

where appropriate.

Important fields may include:

```text
rule_id
attack_type
severity
confidence
source_ip
evidence
description
technical_impact
business_impact
```

Do not add fields unless they serve a concrete purpose.

---

# 28. Evidence Must Be Preserved

A finding should explain WHY it was generated.

Each meaningful detection should retain evidence such as:

* matched pattern,
* suspicious request fragment,
* failure count,
* relevant HTTP path,
* relevant status code.

Do not generate unexplained alerts.

The goal is:

```text
Explainable Detection
```

not:

```text
Black-Box Detection
```

---

# 29. Brute-Force Detection Requires State

A single failed authentication request usually does not prove brute-force activity.

Brute-force detection should consider factors such as:

```text
source IP
time window
number of failed attempts
target account/path
```

Do not label individual login failures as brute force without aggregation logic.

---

# 30. Security Detection Terminology

Use precise terminology.

Prefer:

```text
SQL injection attempt detected
```

over:

```text
Database hacked
```

Prefer:

```text
Possible XSS payload observed
```

over:

```text
XSS vulnerability found
```

A malicious request in a log does not prove that the underlying application is vulnerable.

---

# 31. Risk Terminology

Distinguish:

```text
Threat
Vulnerability
Attack Attempt
Finding
Incident
Compromise
Risk
Impact
```

Do not use these terms interchangeably.

In particular:

```text
Finding != Incident
Attack Attempt != Successful Exploitation
Payload != Vulnerability
```

---

# 32. CLI UX

CLI output should prioritize analyst readability.

A normal finding should make it easy to identify:

```text
Threat Type
Severity
Confidence
Source
Evidence
Technical Impact
Business Impact
Recommended Action
```

Avoid visual noise.

Rich formatting should enhance comprehension, not decorate unnecessarily.

---

# 33. Performance

Do not prematurely optimize.

However, the agent SHOULD avoid obviously inefficient behavior.

For example:

Do NOT:

```text
Call Gemini once for every raw log line.
```

Prefer:

```text
Detect locally.
Deduplicate/group findings.
Call Gemini only for findings requiring enrichment.
```

---

# 34. Security Recommendations

When recommending remediation, distinguish between:

```text
Detection-side action
```

and:

```text
Application/security control
```

Examples:

Detection:

```text
Monitor repeated attempts from the source IP.
```

Prevention:

```text
Use parameterized SQL queries.
```

Do not imply that blocking an IP fixes a vulnerable SQL query.

---

# 35. Comments

Comments should explain:

```text
Why
```

not obvious:

```text
What
```

Bad:

```python
# Loop through events
for event in events:
```

Good:

```python
# Aggregate failures by source IP so isolated authentication
# errors are not incorrectly classified as brute-force attacks.
```

---

# 36. Python Quality Standards

Use:

* clear variable names,
* small focused functions,
* pathlib instead of manual path manipulation,
* dataclasses where appropriate,
* Enum where finite semantic states exist,
* context managers for resources,
* explicit return values.

Avoid:

* hidden global mutable state,
* deeply nested functions,
* excessive inheritance,
* clever metaprogramming,
* premature concurrency.

---

# 37. Definition of Done

Before declaring a feature complete, verify:

```text
[ ] Requirement implemented
[ ] Type hints added
[ ] Useful docstrings added
[ ] Relevant errors handled
[ ] Security logic explained
[ ] Business impact explained
[ ] Tests added/updated
[ ] Tests passing
[ ] No secrets introduced
[ ] No unnecessary dependency added
[ ] Architecture boundaries preserved
[ ] Significant decision recorded in LOGS.md
```

---

# 38. End-of-Session Rule

At the end of each development session, update:

```text
.ai/LOGS.md
```

Summarize:

```text
- What changed
- What was decided
- What files were modified
- What tests were performed
- Known limitations
- Next recommended task
```

Do not overwrite previous history.

Append a new dated entry.

---

# 39. Conflict Resolution

If instructions conflict, follow this priority:

```text
1. Explicit current user instruction
2. Security/correctness requirements
3. .ai/RULES.md
4. .ai/CONTEXT.md
5. Recorded architectural decisions
6. Existing implementation patterns
7. Agent preference
```

If a meaningful conflict exists, state it explicitly.

Do not silently resolve architectural ambiguity.

---

# 40. Final Agent Directive

When uncertain:

```text
Do not invent.
Do not overengineer.
Do not hide uncertainty.
Do not exaggerate security findings.
Do not confuse AI output with verified evidence.
```

Instead:

```text
Inspect.
Verify.
Explain.
Test.
Document.
```

````

### `.ai/LOGS.md`

```markdown
# AI-Augmented SOC Analyst — Development Log

## Purpose

This file is the persistent development memory for AI-assisted coding sessions.

Use it to record:

- architectural decisions,
- implemented features,
- important refactors,
- security decisions,
- dependency changes,
- discovered limitations,
- unresolved questions,
- testing status,
- next development steps.

This file should help a new AI session understand:

```text
What has already been done?
Why was it done this way?
What should happen next?
````

Do NOT delete previous entries.

Append new session entries chronologically.

---

# Project Status

**Project:** AI-Augmented SOC Analyst
**Language:** Python
**Interface:** CLI
**Primary Purpose:** Web/Linux log analysis with deterministic threat detection and optional Gemini-assisted risk analysis.

Current target detections:

```text
- SQL Injection
- XSS
- Brute Force
```

Current intended architecture:

```text
Log
 ↓
Parser
 ↓
Detection Engine
 ↓
Structured Finding
 ↓
Local Risk Scoring
 ↓
Optional Gemini Enrichment
 ↓
CLI Report
```

---

# Decision Registry

Use this section for architectural decisions that future agents should preserve.

Format:

```text
ADR-XXX — Decision title
Status:
Date:
Decision:
Reason:
Consequences:
```

---

## ADR-001 — Deterministic Detection Before AI

**Status:** Accepted
**Date:** Project Initialization

### Decision

Threat detection will be performed locally using deterministic logic such as:

* regex,
* counters,
* time-window aggregation,
* explicit Python rules.

Gemini will only enrich findings after local detection.

### Reason

The core security functionality should remain:

* explainable,
* testable,
* deterministic,
* usable without external API availability.

### Consequences

Gemini API failure must not prevent local detection.

---

## ADR-002 — Minimal Dependency Policy

**Status:** Accepted
**Date:** Project Initialization

### Decision

Use Python standard-library functionality whenever practical.

External dependencies require a concrete justification.

Expected dependencies may include:

```text
rich
google-genai
python-dotenv
pytest
```

### Reason

The project should remain lightweight, understandable, maintainable, and portfolio-friendly.

### Consequences

Agents must not introduce large frameworks merely for convenience.

---

## ADR-003 — Security Findings Must Include Business Context

**Status:** Accepted
**Date:** Project Initialization

### Decision

Important findings should communicate both:

```text
Technical Security Impact
```

and:

```text
Potential Business Impact
```

### Reason

The project is intended to demonstrate the intersection of:

```text
Cybersecurity + Risk Analysis + Business Understanding
```

### Consequences

Risk language must remain proportional to the evidence and must not imply successful compromise without proof.

---

# Current Development Status

## Completed

```text
[ ] Repository structure created
[ ] Python project configuration created
[ ] Core LogEvent model implemented
[ ] Core Finding model implemented
[ ] Apache parser implemented
[ ] Nginx parser implemented
[ ] Linux authentication parser implemented
[ ] SQL Injection detector implemented
[ ] XSS detector implemented
[ ] Brute-force detector implemented
[ ] Risk scorer implemented
[ ] Gemini client implemented
[ ] Rich console reporter implemented
[ ] CLI implemented
[ ] Unit tests implemented
[ ] README completed
```

Update these checkboxes as the project progresses.

---

# Current Known Scope

## MVP

```text
1. Load log file
2. Parse supported log format
3. Normalize records into LogEvent objects
4. Run deterministic security detections
5. Generate Finding objects
6. Calculate local severity/confidence
7. Display findings using Rich
8. Optionally enrich findings through Gemini
9. Explain technical impact
10. Explain potential business impact
```

---

# Backlog

Potential future work:

```text
[ ] Path traversal detector
[ ] Command injection detector
[ ] Scanner/reconnaissance detector
[ ] Suspicious user-agent detector
[ ] Credential-stuffing detection
[ ] JSON report export
[ ] CSV report export
[ ] Configurable detection thresholds
[ ] Detection rule IDs
[ ] Detection rule documentation
[ ] Log anonymization before Gemini requests
[ ] Finding deduplication
[ ] Finding aggregation
[ ] CLI severity filtering
[ ] Offline demo mode
[ ] GitHub Actions test workflow
```

Items in this backlog are NOT automatically approved for implementation.

Do not expand scope without checking current priorities.

---

# Open Questions

Use this section for unresolved design decisions.

```text
- Exact Apache log formats to support?
- Exact Nginx log formats to support?
- Should Linux auth.log support be part of MVP or Phase 2?
- How should confidence be represented?
- How should severity be calculated?
- What brute-force threshold and time window should be the default?
- Should Gemini analyze individual findings or grouped findings?
- What sensitive fields should be masked before Gemini requests?
- Which report export format should be implemented first?
```

Remove or mark questions as resolved when decisions are made.

---

# Session Log Template

Copy the following template at the end of this file after every development session.

---

## YYYY-MM-DD — Session NN

### Session Goal

Describe the main objective of this development session.

```text
Example:
Implement the first version of the SQL Injection detection engine.
```

---

### Context Before Work

Briefly describe the relevant project state before changes.

```text
Example:
LogEvent model exists.
Apache parser exists.
No security detectors have been implemented yet.
```

---

### Decisions Made

Record important technical or architectural decisions.

```text
1. Decision:
   Reason:

2. Decision:
   Reason:
```

Include alternatives when relevant:

```text
Decision:
Use multiple small SQLi regex patterns instead of one large regex.

Reason:
Improves readability and testability.

Rejected alternative:
Single large regex covering all known SQLi patterns.

Why rejected:
Harder to maintain and likely to produce unclear false positives.
```

---

### Work Completed

```text
- 
- 
- 
```

Example:

```text
- Added SQLInjectionDetector.
- Added UNION SELECT detection.
- Added boolean-based SQLi detection.
- Added detector tests.
```

---

### Files Created

```text
- None
```

or:

```text
- src/soc_analyst/detection/sqli.py
- tests/test_sqli_detector.py
```

---

### Files Modified

```text
- None
```

or:

```text
- src/soc_analyst/models/finding.py
- README.md
```

---

### Dependencies Added / Removed

```text
None
```

If a dependency changed:

```text
Added:
- package-name==version

Reason:
...

Security/Maintenance Impact:
...
```

---

### Security Logic Added

For each important security rule:

```text
Detection:
...

Security rationale:
...

Potential false positives:
...

Potential false negatives:
...
```

Example:

```text
Detection:
Boolean-based SQL injection pattern such as "' OR 1=1".

Security rationale:
Attackers may inject boolean expressions to bypass authentication
or manipulate SQL query conditions.

Potential false positives:
Educational content or search queries containing SQL syntax.

Potential false negatives:
Obfuscated or encoded SQL injection payloads.
```

---

### Business Risk Impact

Describe the business relevance of the work.

```text
Technical impact:
...

Potential business impact:
...
```

Do not describe an attack attempt as a successful breach.

---

### Tests Added

```text
- 
- 
```

Example:

```text
- test_detects_union_select
- test_detects_boolean_sqli
- test_ignores_normal_search_query
```

---

### Verification Performed

Commands:

```bash
pytest
```

Results:

```text
Example:
24 tests passed.
```

If tests were not executed:

```text
Tests were not executed.

Reason:
...
```

Never claim tests passed unless they were actually executed.

---

### Bugs / Problems Discovered

```text
None
```

or:

```text
- URL-encoded SQLi payloads are currently not normalized before detection.
- Apache parser does not yet support custom LogFormat configurations.
```

---

### Known Limitations

```text
- 
- 
```

Every non-trivial security detector should have its limitations documented.

---

### Security Concerns

```text
None identified.
```

or:

```text
- Query strings may contain sensitive values.
- Raw requests must not be forwarded directly to Gemini without sanitization.
```

---

### Technical Debt

```text
None
```

or:

```text
- Detection constants are temporarily stored in the detector module.
- A dedicated rule metadata model may be useful after multiple detectors exist.
```

Do not create abstractions merely to eliminate hypothetical technical debt.

---

### Unresolved Questions

```text
- 
- 
```

Example:

```text
- Should URL decoding occur in the parser or detection layer?
```

---

### Next Recommended Task

```text
1.
2.
3.
```

Keep this list short and prioritized.

---

### Current Project State After Session

Summarize what the next AI session needs to know in 3–8 bullets.

```text
- Apache logs can now be parsed.
- SQL Injection detector is operational.
- SQLi detector has 8 unit tests.
- URL decoding has not yet been implemented.
- Gemini integration has not started.
- Next priority is the XSS detector.
```

---

# Example First Session

## YYYY-MM-DD — Session 01

### Session Goal

Initialize project architecture and establish development standards.

### Context Before Work

The project is starting from an empty or near-empty repository.

### Decisions Made

1. Use a modular Python package architecture.
2. Keep deterministic detection independent from Gemini.
3. Use minimal third-party dependencies.
4. Represent security findings using structured models.
5. Separate severity from confidence.
6. Require business-risk explanations for important security findings.

### Work Completed

```text
- Created project context documentation.
- Created strict AI development rules.
- Created persistent development log structure.
```

### Files Created

```text
- .ai/CONTEXT.md
- .ai/RULES.md
- .ai/LOGS.md
```

### Files Modified

```text
None
```

### Dependencies Added / Removed

```text
None
```

### Security Logic Added

```text
No executable detection logic implemented yet.
```

### Business Risk Impact

```text
The project architecture establishes business-risk analysis as a
first-class part of security reporting rather than an afterthought.
```

### Tests Added

```text
None
```

### Verification Performed

```text
Documentation-only initialization.
No code tests required yet.
```

### Bugs / Problems Discovered

```text
None
```

### Known Limitations

```text
No executable application exists yet.
```

### Security Concerns

```text
Future Gemini integration must avoid sending secrets or unnecessary
sensitive log information to external APIs.
```

### Technical Debt

```text
None
```

### Unresolved Questions

```text
- Final severity scoring methodology.
- Final confidence scoring methodology.
- Default brute-force detection threshold.
```

### Next Recommended Task

```text
1. Initialize Python package and pyproject.toml.
2. Implement LogEvent and Finding domain models.
3. Implement the first Apache/Nginx log parser.
```

### Current Project State After Session

```text
- Project development standards are defined.
- AI agent responsibilities are defined.
- Deterministic detection is the architectural baseline.
- Gemini will be used only as an enrichment layer.
- No production Python code exists yet.
```

---

# End-of-Session Instruction for AI Agents

When the user says:

```text
"Bugünkü kararları LOGS.md'ye özetle."
```

or equivalent wording, the AI agent MUST:

```text
1. Inspect the work performed during the current session.
2. Append a new dated Session entry.
3. Record actual decisions, not assumptions.
4. List files actually created or modified.
5. Record tests actually executed.
6. Document security implications.
7. Document business-risk implications.
8. Record known limitations.
9. Record unresolved questions.
10. Define the next 1–3 recommended tasks.
```

The AI MUST NOT:

```text
- Rewrite previous session history.
- Claim tests were run when they were not.
- Claim features exist when they were not implemented.
- Hide unresolved problems.
- Convert speculative ideas into recorded architectural decisions.
```

The final section of every session entry should allow a fresh AI agent to continue development without requiring the entire previous conversation.

```
```
