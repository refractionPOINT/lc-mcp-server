"""
Audit logging framework for LimaCharlie MCP Server.

This module provides a simple, secure audit logging system that:
- Logs security-relevant events to stdout as structured JSON
- Never logs sensitive data (parameters, responses, tokens, etc.)
- Provides severity-based filtering
- Includes minimal overhead for production use

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

# Standard logging for application logs
logger = logging.getLogger(__name__)


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    CRITICAL = 4  # Auth, delete, credentials, isolation
    HIGH = 3      # Create/update rules, configurations
    MEDIUM = 2    # Queries, reads, lists
    LOW = 1       # Metadata, health checks


class AuditAction(Enum):
    """Action types for audit events."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    AUTH = "auth"


class AuditLogger:
    """
    Simple audit logger that writes structured JSON events to stdout.

    This logger is designed to be safe by default - it only logs
    known-safe fields and never logs potentially sensitive data.
    """

    def __init__(self):
        """Initialize the audit logger with configuration from environment."""
        self.enabled = os.getenv("AUDIT_LOG_ENABLED", "true").lower() in ("true", "1", "yes")

        # Parse minimum severity level
        level_str = os.getenv("AUDIT_LOG_LEVEL", "MEDIUM").upper()
        try:
            self.min_severity = AuditSeverity[level_str]
        except KeyError:
            logger.warning(f"Invalid AUDIT_LOG_LEVEL '{level_str}', defaulting to MEDIUM")
            self.min_severity = AuditSeverity.MEDIUM

        self.include_low = os.getenv("AUDIT_LOG_INCLUDE_LOW", "false").lower() in ("true", "1", "yes")

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
            event["error_message"] = self._sanitize_error_message(error_message)
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

        # Write to stdout as JSON
        self._write_audit_event(event)

    def _sanitize_error_message(self, error_message: str) -> str:
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
        # Note: This is conservative - we prefer to truncate rather than leak
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
                # If we detect potential sensitive data, return a generic message
                return "Error occurred (details redacted for security)"

        return error_message

    def _write_audit_event(self, event: Dict[str, Any]) -> None:
        """
        Write an audit event to stdout.

        Args:
            event: The audit event dictionary
        """
        try:
            # Write to stdout with immediate flush
            json_str = json.dumps(event, ensure_ascii=False)
            print(f"AUDIT: {json_str}", file=sys.stdout, flush=True)
        except Exception as e:
            # If audit logging fails, log to standard logger but don't fail the operation
            logger.error(f"Failed to write audit log: {e}")


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
