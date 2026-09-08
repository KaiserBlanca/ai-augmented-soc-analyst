"""Detection engine package containing deterministic threat detection rules and base contracts."""

from soc_analyst.detection.base import BaseDetector
from soc_analyst.detection.sqli import SQLInjectionDetector
from soc_analyst.detection.xss import XSSDetector

__all__ = [
    "BaseDetector",
    "SQLInjectionDetector",
    "XSSDetector",
]
