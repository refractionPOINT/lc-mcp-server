"""
Audit logging framework for LimaCharlie MCP Server.

This module provides a Pythonic audit logging system using Python's
built-in logging infrastructure (Logger, Handler, Formatter, Filter).

Features:
- Logs security-relevant events to stdout as structured JSON
- Never logs sensitive data (parameters, responses, tokens, etc.)
- Provides severity-based filtering via standard logging levels
- Integrates seamlessly with Python's logging ecosystem

Configuration via environment variables:
- AUDIT_LOG_ENABLED: Enable/disable audit logging (default: true)
- AUDIT_LOG_LEVEL: Minimum severity to log - CRITICAL, HIGH, MEDIUM, LOW (default: MEDIUM)
- AUDIT_LOG_INCLUDE_LOW: Include LOW severity events (default: false)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
import re


class AuditSeverity(Enum):
    """Severity levels for audit events mapped to Python logging levels."""
    CRITICAL = logging.CRITICAL  # Auth, delete, credentials, isolation
    HIGH = logging.ERROR         # Create/update rules, configurations
    MEDIUM = logging.WARNING     # Queries, reads, lists
    LOW = logging.INFO           # Metadata, health checks


class AuditAction(Enum):
    """Action types for audit events."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    AUTH = "auth"


class AuditLogFilter(logging.Filter):
    """
    Filter for audit log records based on severity configuration.

    This filter implements the AUDIT_LOG_INCLUDE_LOW logic and ensures
    only appropriate severity levels are logged.
    """

    def __init__(self, min_severity: AuditSeverity, include_low: bool = False):
        """
        Initialize the audit log filter.

        Args:
            min_severity: Minimum severity level to log
            include_low: Whether to include LOW severity events
        """
        super().__init__()
        self.min_severity = min_severity
        self.include_low = include_low

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Determine if a record should be logged.

        Args:
            record: The log record to filter

        Returns:
            True if the record should be logged, False otherwise
        """
        # Check if this is an audit record (has audit_event attribute)
        if not hasattr(record, 'audit_event'):
            return True  # Pass through non-audit logs

        severity = getattr(record, 'audit_severity', None)
        if severity is None:
            return True

        # Always exclude LOW unless explicitly enabled
        if severity == AuditSeverity.LOW:
            return self.include_low

        # Check if severity meets minimum threshold
        return severity.value >= self.min_severity.value


class AuditLogFormatter(logging.Formatter):
    """
    Formatter for audit log records that outputs structured JSON.

    This formatter extracts audit event data from the LogRecord and
    formats it as JSON with safe fields only.
    """

    def format(self, record: logging.LogRecord) -> str:
        """
        Format a log record as JSON.

        Args:
            record: The log record to format

        Returns:
            JSON string representation of the audit event
        """
        # Check if this is an audit event (has audit_event attribute)
        if not hasattr(record, 'audit_event'):
            # Fall back to default formatting for non-audit logs
            return super().format(record)

        # Extract the audit event data
        event = record.audit_event

        # Sanitize error message if present
        if 'error_message' in event and event['error_message']:
            event['error_message'] = self._sanitize_error_message(event['error_message'])

        try:
            # Write as JSON with AUDIT prefix for easy filtering
            json_str = json.dumps(event, ensure_ascii=False)
            return f"AUDIT: {json_str}"
        except Exception as e:
            # If JSON serialization fails, return a safe error message
            return f"AUDIT: {{\"error\": \"Failed to serialize audit event: {type(e).__name__}\"}}"

    @staticmethod
    def _sanitize_error_message(error_message: str) -> str:
        """
        Sanitize error messages to remove potentially sensitive information.

        Args:
            error_message: The raw error message

        Returns:
            A sanitized error message safe for logging
        """
        # Truncate very long messages
        if len(error_message) > 500:
            error_message = error_message[:497] + "..."

        # Basic sanitization - remove common patterns that might leak info
        sensitive_patterns = [
            "api_key=",
            "apiKey=",
            "secret=",
            "password=",
            "token=",
            "jwt=",
            "bearer ",
            "authorization:",
        ]

        lower_msg = error_message.lower()
        for pattern in sensitive_patterns:
            if pattern in lower_msg:
                return "Error occurred (details redacted for security)"

        return error_message


class AuditLogHandler(logging.StreamHandler):
    """
    Handler for audit logs that writes to stdout.

    This handler ensures audit logs are written to stdout with immediate
    flushing for real-time visibility.
    """

    def __init__(self):
        """Initialize the handler with stdout stream."""
        super().__init__(stream=sys.stdout)
        # Set the formatter
        self.setFormatter(AuditLogFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        """
        Emit a log record.

        Args:
            record: The log record to emit
        """
        try:
            super().emit(record)
            # Ensure immediate flush for audit logs
            self.flush()
        except Exception:
            # If emit fails, use handleError but don't fail the operation
            self.handleError(record)


class AuditLogger:
    """
    Audit logger using Python's logging infrastructure.

    This class provides a clean interface for audit logging while
    leveraging Python's built-in logging system for filtering,
    formatting, and output.
    """

    def __init__(self):
        """Initialize the audit logger with configuration from environment."""
        self.enabled = os.getenv("AUDIT_LOG_ENABLED", "true").lower() in ("true", "1", "yes")

        # Parse minimum severity level
        level_str = os.getenv("AUDIT_LOG_LEVEL", "MEDIUM").upper()
        try:
            self.min_severity = AuditSeverity[level_str]
        except KeyError:
            logging.warning(f"Invalid AUDIT_LOG_LEVEL '{level_str}', defaulting to MEDIUM")
            self.min_severity = AuditSeverity.MEDIUM

        self.include_low = os.getenv("AUDIT_LOG_INCLUDE_LOW", "false").lower() in ("true", "1", "yes")

        # Create a dedicated logger for audit events
        self.logger = logging.getLogger("limacharlie.audit")
        self.logger.setLevel(logging.DEBUG)  # Let filter handle actual filtering
        self.logger.propagate = False  # Don't propagate to root logger

        # Add our custom handler
        handler = AuditLogHandler()
        handler.addFilter(AuditLogFilter(self.min_severity, self.include_low))
        self.logger.addHandler(handler)

    def should_log(self, severity: AuditSeverity) -> bool:
        """
        Determine if an event should be logged based on configuration.

        Args:
            severity: The severity level of the event

        Returns:
            True if the event should be logged, False otherwise
        """
        if not self.enabled:
            return False

        # Always exclude LOW unless explicitly enabled
        if severity == AuditSeverity.LOW:
            return self.include_low

        # Check if severity meets minimum threshold
        return severity.value >= self.min_severity.value

    def log_event(
        self,
        event_type: str,
        severity: AuditSeverity,
        action: AuditAction,
        status: str,
        user_id: Optional[str] = None,
        organization_id: Optional[str] = None,
        status_code: Optional[int] = None,
        error_message: Optional[str] = None,
        request_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        duration_ms: Optional[int] = None,
        additional_safe_fields: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Log an audit event with safe fields only.

        This method only logs metadata and context - never parameters,
        responses, or any potentially sensitive data.

        Args:
            event_type: The type of event (typically the tool/function name)
            severity: Event severity level
            action: Type of action being performed
            status: "success" or "failure"
            user_id: User identifier (uid)
            organization_id: Organization identifier (oid)
            status_code: HTTP status code if applicable
            error_message: Generic error message (no sensitive details)
            request_id: Request correlation ID
            source_ip: Source IP address of the request
            user_agent: User agent string
            duration_ms: Operation duration in milliseconds
            additional_safe_fields: Additional known-safe fields to include
        """
        if not self.should_log(severity):
            return

        # Build the audit event with only safe fields
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity.name,
            "action": action.value,
            "status": status,
        }

        # Add optional fields if provided
        if user_id is not None:
            event["user_id"] = user_id
        if organization_id is not None:
            event["organization_id"] = organization_id
        if status_code is not None:
            event["status_code"] = status_code
        if error_message is not None:
            event["error_message"] = error_message
        if request_id is not None:
            event["request_id"] = request_id
        if source_ip is not None:
            event["source_ip"] = source_ip
        if user_agent is not None:
            event["user_agent"] = user_agent
        if duration_ms is not None:
            event["duration_ms"] = duration_ms

        # Add any additional safe fields
        if additional_safe_fields:
            event.update(additional_safe_fields)

        # Log using Python's logging infrastructure
        # Attach event data and severity to the LogRecord
        extra = {
            'audit_event': event,
            'audit_severity': severity
        }
        self.logger.log(severity.value, "Audit event", extra=extra)


# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """
    Get the global audit logger instance.

    Returns:
        The global AuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


def infer_action_from_tool_name(tool_name: str) -> AuditAction:
    """
    Infer the action type from the tool/function name.

    Args:
        tool_name: The name of the tool or function

    Returns:
        The inferred AuditAction
    """
    tool_lower = tool_name.lower()

    # Check for authentication-related operations
    if "auth" in tool_lower or "login" in tool_lower or "token" in tool_lower:
        return AuditAction.AUTH

    # Check for delete operations
    if tool_lower.startswith("delete_") or tool_lower.startswith("remove_"):
        return AuditAction.DELETE

    # Check for create operations
    if tool_lower.startswith("create_") or tool_lower.startswith("add_"):
        return AuditAction.CREATE

    # Check for update operations
    if tool_lower.startswith("set_") or tool_lower.startswith("update_") or tool_lower.startswith("modify_"):
        return AuditAction.UPDATE

    # Check for read operations
    if (tool_lower.startswith("get_") or tool_lower.startswith("list_") or
        tool_lower.startswith("search_") or tool_lower.startswith("run_query") or
        tool_lower.startswith("query_")):
        return AuditAction.READ

    # Default to execute for everything else
    return AuditAction.EXECUTE
