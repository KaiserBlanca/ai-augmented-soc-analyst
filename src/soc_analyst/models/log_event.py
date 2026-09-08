"""Normalized immutable log event model for the SOC analysis pipeline."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(frozen=True)
class LogEvent:
    """Represents an immutable, normalized log event parsed from raw telemetry.

    This dataclass acts as the foundational data contract across all log parsers
    (e.g., Apache, Nginx, Linux Auth) and downstream detection engines. Immutability
    guarantees that ingested log evidence cannot be altered during the evaluation pipeline.

    Attributes:
        raw_line: The original unparsed log line string, retained for forensic auditability.
        timestamp: Parsed event timestamp, or None if unavailable or unparseable.
        source_ip: Originating client/host IP address associated with the event.
        method: HTTP request method (e.g., 'GET', 'POST') or command/action name if applicable.
        path: Requested URL path, endpoint, or targeted system resource.
        status_code: HTTP response status code or system status code if applicable.
        user_agent: HTTP User-Agent client header string if present.
        user: Username involved in the event, particularly for authentication logs.
    """

    raw_line: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    user: Optional[str] = None
