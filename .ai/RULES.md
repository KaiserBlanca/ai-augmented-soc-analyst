````markdown
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

```
```
