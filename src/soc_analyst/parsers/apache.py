"""Apache HTTP Server access log parser.

This module provides deterministic parsing capabilities for Apache HTTP Server access
logs in both Common Log Format (CLF) and Combined Log Format.

It extracts structured metadata into immutable `LogEvent` domain models while ensuring
graceful degradation on corrupted, malformed, or incomplete log entries.

Format Reference:
    - Common Log Format (CLF):
        %h %l %u %t \"%r\" %>s %b
        Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326

    - Combined Log Format:
        %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"
        Example: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://example.com" "Mozilla/5.0"
"""

from collections.abc import Iterable
from datetime import datetime
import logging
from pathlib import Path
import re
from typing import Optional, Union

from soc_analyst.models.log_event import LogEvent

logger = logging.getLogger(__name__)

# Apache Combined Log Format:
# Captures remote host (%h), RFC 1413 identity (%l), remote user (%u),
# request timestamp (%t), HTTP request line (%r), status code (%>s),
# response size (%b), Referer header, and User-Agent header.
APACHE_COMBINED_PATTERN: re.Pattern[str] = re.compile(
    r"^(?P<host>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>.*?)"\s+'
    r"(?P<status>\d{3}|-)\s+"
    r"(?P<bytes>\d+|-)\s+"
    r'"(?P<referer>.*?)"\s+'
    r'"(?P<user_agent>.*)"\s*$'
)

# Apache Common Log Format (CLF):
# Captures standard 7 fields without Referer and User-Agent headers.
APACHE_COMMON_PATTERN: re.Pattern[str] = re.compile(
    r"^(?P<host>\S+)\s+"
    r"(?P<ident>\S+)\s+"
    r"(?P<user>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>.*?)"\s+'
    r"(?P<status>\d{3}|-)\s+"
    r"(?P<bytes>\d+|-)\s*$"
)


def _parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse an Apache log timestamp string into a datetime object.

    Handles standard Apache datetime format with timezone offset
    (e.g., '10/Oct/2000:13:55:36 -0700') and timezone-naive fallback.
    Degrades gracefully by logging a warning and returning None if format is unparseable.

    Args:
        timestamp_str: Raw timestamp extracted from inside square brackets.

    Returns:
        A datetime object if parsed successfully, or None if malformed or empty.
    """
    cleaned = timestamp_str.strip()
    if not cleaned or cleaned == "-":
        return None

    # Standard Apache format: '09/Sep/2026:01:00:00 +0000'
    try:
        return datetime.strptime(cleaned, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        pass

    # Fallback format without timezone offset: '09/Sep/2026:01:00:00'
    try:
        return datetime.strptime(cleaned, "%d/%b/%Y:%H:%M:%S")
    except ValueError as err:
        logger.warning(
            "Malformed timestamp encountered in Apache log line: '%s' (%s)",
            cleaned,
            err,
        )
        return None


def _parse_request_field(request_str: str) -> tuple[Optional[str], Optional[str]]:
    """Extract HTTP method and target resource path from the HTTP request line.

    Gracefully extracts the method (e.g. 'GET', 'POST') and endpoint path
    (e.g. '/index.php?id=1') from the request string ('METHOD PATH PROTOCOL').
    Handles malformed, partial, or non-standard request lines without raising exceptions.

    Args:
        request_str: The unescaped request string captured between quotes.

    Returns:
        A tuple of (method, path). Either or both may be None if unavailable or malformed.
    """
    cleaned = request_str.strip()
    if not cleaned or cleaned == "-":
        return None, None

    parts = cleaned.split()
    if len(parts) == 1:
        # Single token: could be an isolated verb or invalid fragment
        return parts[0], None

    if len(parts) == 2:
        # HTTP/0.9 or missing protocol: e.g. 'GET /path'
        return parts[0], parts[1]

    # Standard format: 'METHOD PATH PROTOCOL' (e.g. 'GET /api/v1/resource HTTP/1.1')
    # If the last element is the protocol token, everything in between is the path.
    last_part = parts[-1]
    if last_part.startswith(("HTTP/", "http/")):
        method = parts[0]
        path = " ".join(parts[1:-1])
        return method, path

    # Non-standard 3+ token request without HTTP protocol prefix
    return parts[0], " ".join(parts[1:])


def _parse_status_code(status_str: str) -> Optional[int]:
    """Safely convert HTTP status code string to integer.

    Args:
        status_str: Raw status code string (e.g., '200', '404', or '-').

    Returns:
        Integer status code, or None if unavailable or non-numeric.
    """
    cleaned = status_str.strip()
    if not cleaned or cleaned == "-":
        return None

    try:
        return int(cleaned)
    except ValueError as err:
        logger.warning(
            "Malformed HTTP status code encountered: '%s' (%s)", cleaned, err
        )
        return None


class ApacheLogParser:
    """Parser for Apache HTTP Server access logs.

    Supports both Common Log Format (CLF) and Combined Log Format. Operates
    defensively, ensuring that malformed, corrupted, or unparseable lines do not
    crash the application (graceful degradation).
    """

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single Apache log line into a LogEvent domain object.

        First attempts to match against the Combined Log Format. If that fails,
        attempts Common Log Format. If neither matches or the line is empty,
        returns None and logs a diagnostic warning.

        Args:
            line: Single raw log line string from Apache access log.

        Returns:
            A populated LogEvent instance if parsed successfully, or None if the
            line is malformed, unrecognized, or blank.
        """
        if not line or not line.strip():
            logger.debug("Skipping empty or whitespace-only log line.")
            return None

        raw_line = line.rstrip("\r\n")

        # 1. Attempt Combined format match first (more specific)
        match = APACHE_COMBINED_PATTERN.match(raw_line)
        is_combined = True

        # 2. If Combined fails, attempt Common format match
        if not match:
            match = APACHE_COMMON_PATTERN.match(raw_line)
            is_combined = False

        # 3. If neither matches, line is malformed or in an unsupported format
        if not match:
            logger.warning(
                "Failed to parse Apache log line (malformed or unrecognized format): '%s'",
                raw_line,
            )
            return None

        groups = match.groupdict()

        # Extract source IP / host
        host_str = groups.get("host", "").strip()
        source_ip: Optional[str] = host_str if host_str and host_str != "-" else None

        # Extract authenticated user
        user_str = groups.get("user", "").strip()
        user: Optional[str] = user_str if user_str and user_str != "-" else None

        # Extract and parse timestamp
        raw_time = groups.get("time", "")
        timestamp = _parse_timestamp(raw_time)

        # Extract and parse request line (method and path)
        raw_request = groups.get("request", "")
        method, path = _parse_request_field(raw_request)

        # Extract and parse status code
        raw_status = groups.get("status", "")
        status_code = _parse_status_code(raw_status)

        # Extract user agent if Combined format
        user_agent: Optional[str] = None
        if is_combined:
            raw_ua = groups.get("user_agent", "").strip()
            if raw_ua and raw_ua != "-":
                user_agent = raw_ua

        return LogEvent(
            raw_line=raw_line,
            timestamp=timestamp,
            source_ip=source_ip,
            method=method,
            path=path,
            status_code=status_code,
            user_agent=user_agent,
            user=user,
        )

    def parse_lines(self, lines: Iterable[str]) -> list[LogEvent]:
        """Parse an iterable of Apache log lines into a list of LogEvent objects.

        Malformed lines are skipped gracefully without aborting the parsing of subsequent lines.

        Args:
            lines: An iterable sequence of raw log lines.

        Returns:
            List of successfully parsed LogEvent objects.
        """
        events: list[LogEvent] = []
        for line in lines:
            event = self.parse_line(line)
            if event is not None:
                events.append(event)
        return events

    def parse_file(
        self, file_path: Union[str, Path], encoding: str = "utf-8"
    ) -> list[LogEvent]:
        """Parse an Apache log file from disk into a list of LogEvent objects.

        Safely handles file reading errors (e.g. non-existent files or invalid
        byte sequences) by replacing invalid characters and logging errors
        instead of terminating execution.

        Args:
            file_path: Filesystem path to the log file.
            encoding: Text encoding to use when reading the file (defaults to 'utf-8').

        Returns:
            List of successfully parsed LogEvent objects.
        """
        path = Path(file_path)
        if not path.is_file():
            logger.error(
                "Apache log file does not exist or is not a regular file: %s",
                file_path,
            )
            return []

        try:
            with open(path, mode="r", encoding=encoding, errors="replace") as f:
                return self.parse_lines(f)
        except OSError as err:
            logger.error("Failed to read Apache log file '%s': %s", file_path, err)
            return []


# Module-level convenience functions using a shared default parser instance
_default_parser = ApacheLogParser()


def parse_line(line: str) -> Optional[LogEvent]:
    """Parse a single Apache log line using the default ApacheLogParser.

    Args:
        line: Raw log line string.

    Returns:
        LogEvent if valid, or None if malformed/unparseable.
    """
    return _default_parser.parse_line(line)


def parse_lines(lines: Iterable[str]) -> list[LogEvent]:
    """Parse multiple Apache log lines using the default ApacheLogParser.

    Args:
        lines: Iterable collection of raw log line strings.

    Returns:
        List of successfully parsed LogEvent objects.
    """
    return _default_parser.parse_lines(lines)


def parse_file(
    file_path: Union[str, Path], encoding: str = "utf-8"
) -> list[LogEvent]:
    """Parse an Apache log file using the default ApacheLogParser.

    Args:
        file_path: Filesystem path to the Apache log file.
        encoding: Text encoding (defaults to 'utf-8').

    Returns:
        List of successfully parsed LogEvent objects.
    """
    return _default_parser.parse_file(file_path, encoding=encoding)
