"""Abstract base detector definition for deterministic threat detection engines."""

from abc import ABC, abstractmethod
from collections.abc import Iterable

from soc_analyst.models.finding import Finding
from soc_analyst.models.log_event import LogEvent


class BaseDetector(ABC):
    """Abstract base class for all deterministic security threat detectors.

    Detectors evaluate normalized LogEvent instances against domain-specific
    signatures, patterns, or heuristics and emit structured Finding objects.
    All detection rules must be explainable, testable offline, and maintain
    strict separation between detection logic and presentation or AI enrichment.
    """

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., 'SEC-SQLI-001', 'SEC-XSS-001')."""
        pass

    @property
    @abstractmethod
    def attack_type(self) -> str:
        """Categorical attack name (e.g., 'SQL_INJECTION', 'XSS')."""
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Descriptive human-readable name of the detector."""
        pass

    @abstractmethod
    def detect(self, event: LogEvent) -> list[Finding]:
        """Analyze a single LogEvent for potential threat patterns.

        Args:
            event: Normalized LogEvent instance to evaluate.

        Returns:
            A list of Finding objects if threats are identified, or an empty list.
        """
        pass

    def detect_all(self, events: Iterable[LogEvent]) -> list[Finding]:
        """Analyze a collection of LogEvent instances and aggregate all findings.

        Args:
            events: An iterable collection of LogEvent objects.

        Returns:
            Aggregated list of Finding objects across all evaluated events.
        """
        findings: list[Finding] = []
        for event in events:
            findings.extend(self.detect(event))
        return findings
