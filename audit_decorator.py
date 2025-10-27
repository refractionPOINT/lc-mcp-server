"""
Audit logging decorator for LimaCharlie MCP Server tools.

This module provides a decorator that automatically logs audit events
for tool function calls without logging sensitive data.
"""

import functools
import logging
import time
import uuid
from contextvars import ContextVar
from typing import Any, Callable, Optional

from audit_logger import (
    AuditAction,
    AuditSeverity,
    get_audit_logger,
    infer_action_from_tool_name,
)

logger = logging.getLogger(__name__)

# Context variables for request metadata (these should be set by middleware)
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
source_ip_var: ContextVar[Optional[str]] = ContextVar("source_ip", default=None)
user_agent_var: ContextVar[Optional[str]] = ContextVar("user_agent", default=None)


def audit_log(severity: AuditSeverity, action: Optional[AuditAction] = None):
    """
    Decorator to automatically log audit events for tool functions.

    This decorator:
    - Logs the start of an operation
    - Logs the completion with status (success/failure)
    - Captures duration
    - Extracts safe context (user, org, request metadata)
    - Never logs parameters or response data

    Args:
        severity: The severity level for this operation
        action: Optional explicit action type (auto-inferred if not provided)

    Example:
        @audit_log(severity=AuditSeverity.CRITICAL, action=AuditAction.DELETE)
        async def delete_sensor(sid: str, ctx: Context):
            # ... implementation ...
            pass
    """

    def decorator(func: Callable) -> Callable:
        # Infer action from function name if not provided
        action_type = action if action is not None else infer_action_from_tool_name(func.__name__)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            return await _execute_with_audit(func, severity, action_type, args, kwargs, is_async=True)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            import asyncio
            # Use run_in_executor for sync functions to avoid blocking
            loop = asyncio.get_event_loop()
            return loop.run_in_executor(
                None,
                lambda: _execute_with_audit_sync(func, severity, action_type, args, kwargs)
            )

        # Return the appropriate wrapper based on whether the function is async
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


async def _execute_with_audit(
    func: Callable,
    severity: AuditSeverity,
    action: AuditAction,
    args: tuple,
    kwargs: dict,
    is_async: bool
) -> Any:
    """
    Execute a function with audit logging (async version).

    Args:
        func: The function to execute
        severity: Audit event severity
        action: Audit action type
        args: Function positional arguments
        kwargs: Function keyword arguments
        is_async: Whether the function is async

    Returns:
        The function result
    """
    audit_logger = get_audit_logger()
    start_time = time.time()

    # Extract safe context
    context = _extract_safe_context(kwargs)

    # Generate request ID if not present
    req_id = request_id_var.get() or str(uuid.uuid4())

    # Log operation start
    audit_logger.log_event(
        event_type=func.__name__,
        severity=severity,
        action=action,
        status="started",
        user_id=context.get("user_id"),
        organization_id=context.get("organization_id"),
        request_id=req_id,
        source_ip=source_ip_var.get(),
        user_agent=user_agent_var.get(),
    )

    try:
        # Execute the function
        if is_async:
            result = await func(*args, **kwargs)
        else:
            result = func(*args, **kwargs)

        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Log success
        audit_logger.log_event(
            event_type=func.__name__,
            severity=severity,
            action=action,
            status="success",
            user_id=context.get("user_id"),
            organization_id=context.get("organization_id"),
            status_code=200,
            request_id=req_id,
            source_ip=source_ip_var.get(),
            user_agent=user_agent_var.get(),
            duration_ms=duration_ms,
        )

        return result

    except Exception as e:
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Extract HTTP status code if available
        status_code = getattr(e, "status_code", None) or 500

        # Log failure with generic error message
        error_type = type(e).__name__
        audit_logger.log_event(
            event_type=func.__name__,
            severity=severity,
            action=action,
            status="failure",
            user_id=context.get("user_id"),
            organization_id=context.get("organization_id"),
            status_code=status_code,
            error_message=f"{error_type}",  # Only log error type, not message
            request_id=req_id,
            source_ip=source_ip_var.get(),
            user_agent=user_agent_var.get(),
            duration_ms=duration_ms,
        )

        # Re-raise the exception
        raise


def _execute_with_audit_sync(
    func: Callable,
    severity: AuditSeverity,
    action: AuditAction,
    args: tuple,
    kwargs: dict
) -> Any:
    """
    Execute a function with audit logging (sync version).

    This is used for synchronous functions that need audit logging.

    Args:
        func: The function to execute
        severity: Audit event severity
        action: Audit action type
        args: Function positional arguments
        kwargs: Function keyword arguments

    Returns:
        The function result
    """
    audit_logger = get_audit_logger()
    start_time = time.time()

    # Extract safe context
    context = _extract_safe_context(kwargs)

    # Generate request ID if not present
    req_id = request_id_var.get() or str(uuid.uuid4())

    # Log operation start
    audit_logger.log_event(
        event_type=func.__name__,
        severity=severity,
        action=action,
        status="started",
        user_id=context.get("user_id"),
        organization_id=context.get("organization_id"),
        request_id=req_id,
        source_ip=source_ip_var.get(),
        user_agent=user_agent_var.get(),
    )

    try:
        # Execute the function
        result = func(*args, **kwargs)

        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Log success
        audit_logger.log_event(
            event_type=func.__name__,
            severity=severity,
            action=action,
            status="success",
            user_id=context.get("user_id"),
            organization_id=context.get("organization_id"),
            status_code=200,
            request_id=req_id,
            source_ip=source_ip_var.get(),
            user_agent=user_agent_var.get(),
            duration_ms=duration_ms,
        )

        return result

    except Exception as e:
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)

        # Extract HTTP status code if available
        status_code = getattr(e, "status_code", None) or 500

        # Log failure with generic error message
        error_type = type(e).__name__
        audit_logger.log_event(
            event_type=func.__name__,
            severity=severity,
            action=action,
            status="failure",
            user_id=context.get("user_id"),
            organization_id=context.get("organization_id"),
            status_code=status_code,
            error_message=f"{error_type}",  # Only log error type, not message
            request_id=req_id,
            source_ip=source_ip_var.get(),
            user_agent=user_agent_var.get(),
            duration_ms=duration_ms,
        )

        # Re-raise the exception
        raise


def _extract_safe_context(kwargs: dict) -> dict:
    """
    Extract safe context information from function kwargs.

    This function only extracts known-safe fields that don't contain
    sensitive data. We look for 'oid' (organization ID) and try to
    extract user ID from the Context object if present.

    Args:
        kwargs: Function keyword arguments

    Returns:
        Dictionary with safe context fields
    """
    context = {}

    # Extract organization ID if present
    if "oid" in kwargs:
        context["organization_id"] = kwargs["oid"]

    # Try to extract user ID from Context object
    # The Context object is passed to all tools but we need to be careful
    # not to access any sensitive data from it
    if "ctx" in kwargs:
        try:
            # Try to get user ID from context variables
            # This is safe because we're only reading metadata, not credentials
            from server import uid_auth_context_var, current_oid_context_var

            uid_auth = uid_auth_context_var.get()
            if uid_auth and len(uid_auth) > 0:
                context["user_id"] = uid_auth[0]  # uid is first element

            # Get current OID from context if not in kwargs
            if "organization_id" not in context:
                current_oid = current_oid_context_var.get()
                if current_oid:
                    context["organization_id"] = current_oid

        except Exception as e:
            # If we can't extract context, just continue without it
            logger.debug(f"Could not extract context from tool call: {e}")

    return context


def set_request_metadata(request_id: str, source_ip: Optional[str] = None, user_agent: Optional[str] = None):
    """
    Set request metadata for audit logging.

    This should be called by middleware at the start of each request.

    Args:
        request_id: Unique request identifier
        source_ip: Source IP address of the request
        user_agent: User agent string from the request
    """
    request_id_var.set(request_id)
    if source_ip:
        source_ip_var.set(source_ip)
    if user_agent:
        user_agent_var.set(user_agent)


def clear_request_metadata():
    """
    Clear request metadata.

    This should be called by middleware at the end of each request.
    """
    request_id_var.set(None)
    source_ip_var.set(None)
    user_agent_var.set(None)
