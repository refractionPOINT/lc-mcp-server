"""
Tests for audit logging framework.

This test suite verifies that:
1. Audit events are logged correctly
2. Sensitive data is never logged
3. Severity filtering works correctly
4. Performance impact is minimal
"""

import json
import os
import sys
import time
import unittest
from io import StringIO
from unittest.mock import patch, MagicMock

from audit_logger import (
    AuditLogger,
    AuditSeverity,
    AuditAction,
    get_audit_logger,
    infer_action_from_tool_name,
)
from audit_decorator import audit_log


class TestAuditLogger(unittest.TestCase):
    """Test the AuditLogger class."""

    def setUp(self):
        """Set up test fixtures."""
        # Reset environment variables
        os.environ["AUDIT_LOG_ENABLED"] = "true"
        os.environ["AUDIT_LOG_LEVEL"] = "MEDIUM"
        os.environ["AUDIT_LOG_INCLUDE_LOW"] = "false"

        # Create a fresh logger instance
        self.logger = AuditLogger()

    def test_logger_enabled_by_default(self):
        """Test that audit logging is enabled by default."""
        logger = AuditLogger()
        self.assertTrue(logger.enabled)

    def test_logger_can_be_disabled(self):
        """Test that audit logging can be disabled via environment variable."""
        os.environ["AUDIT_LOG_ENABLED"] = "false"
        logger = AuditLogger()
        self.assertFalse(logger.enabled)

    def test_severity_filtering(self):
        """Test that severity filtering works correctly."""
        # Set level to HIGH
        os.environ["AUDIT_LOG_LEVEL"] = "HIGH"
        logger = AuditLogger()

        # HIGH and CRITICAL should be logged
        self.assertTrue(logger.should_log(AuditSeverity.CRITICAL))
        self.assertTrue(logger.should_log(AuditSeverity.HIGH))

        # MEDIUM and LOW should not be logged
        self.assertFalse(logger.should_log(AuditSeverity.MEDIUM))
        self.assertFalse(logger.should_log(AuditSeverity.LOW))

    def test_low_severity_filtering(self):
        """Test that LOW severity events are filtered unless explicitly enabled."""
        # By default, LOW is excluded
        logger = AuditLogger()
        self.assertFalse(logger.should_log(AuditSeverity.LOW))

        # Enable LOW explicitly
        os.environ["AUDIT_LOG_INCLUDE_LOW"] = "true"
        logger = AuditLogger()
        self.assertTrue(logger.should_log(AuditSeverity.LOW))

    def test_audit_event_structure(self):
        """Test that audit events have the correct structure."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.logger.log_event(
                event_type="test_function",
                severity=AuditSeverity.HIGH,
                action=AuditAction.CREATE,
                status="success",
                user_id="test-user",
                organization_id="test-org",
                status_code=200,
                request_id="test-request-123",
                source_ip="1.2.3.4",
                user_agent="test-agent/1.0",
                duration_ms=100
            )

            output = fake_out.getvalue()
            self.assertIn("AUDIT:", output)

            # Parse the JSON
            json_str = output.replace("AUDIT: ", "").strip()
            event = json.loads(json_str)

            # Verify all fields are present
            self.assertEqual(event["event_type"], "test_function")
            self.assertEqual(event["severity"], "HIGH")
            self.assertEqual(event["action"], "create")
            self.assertEqual(event["status"], "success")
            self.assertEqual(event["user_id"], "test-user")
            self.assertEqual(event["organization_id"], "test-org")
            self.assertEqual(event["status_code"], 200)
            self.assertEqual(event["request_id"], "test-request-123")
            self.assertEqual(event["source_ip"], "1.2.3.4")
            self.assertEqual(event["user_agent"], "test-agent/1.0")
            self.assertEqual(event["duration_ms"], 100)
            self.assertIn("timestamp", event)

    def test_error_message_sanitization(self):
        """Test that error messages are sanitized to remove sensitive data."""
        # Test with potentially sensitive error message
        sanitized = self.logger._sanitize_error_message("Error: api_key=secret123 failed")
        self.assertEqual(sanitized, "Error occurred (details redacted for security)")

        sanitized = self.logger._sanitize_error_message("Invalid token=abc123")
        self.assertEqual(sanitized, "Error occurred (details redacted for security)")

        # Test with safe error message
        sanitized = self.logger._sanitize_error_message("Connection timeout")
        self.assertEqual(sanitized, "Connection timeout")

    def test_long_error_message_truncation(self):
        """Test that very long error messages are truncated."""
        long_message = "Error: " + ("x" * 1000)
        sanitized = self.logger._sanitize_error_message(long_message)
        self.assertEqual(len(sanitized), 500)
        self.assertTrue(sanitized.endswith("..."))

    def test_optional_fields_omitted(self):
        """Test that optional fields are omitted when not provided."""
        with patch('sys.stdout', new=StringIO()) as fake_out:
            self.logger.log_event(
                event_type="test_function",
                severity=AuditSeverity.HIGH,
                action=AuditAction.READ,
                status="success"
            )

            output = fake_out.getvalue()
            json_str = output.replace("AUDIT: ", "").strip()
            event = json.loads(json_str)

            # These fields should be present
            self.assertIn("event_type", event)
            self.assertIn("severity", event)
            self.assertIn("action", event)
            self.assertIn("status", event)

            # These optional fields should not be present
            self.assertNotIn("user_id", event)
            self.assertNotIn("organization_id", event)
            self.assertNotIn("error_message", event)


class TestActionInference(unittest.TestCase):
    """Test action type inference from tool names."""

    def test_delete_action_inference(self):
        """Test that delete actions are inferred correctly."""
        self.assertEqual(infer_action_from_tool_name("delete_sensor"), AuditAction.DELETE)
        self.assertEqual(infer_action_from_tool_name("remove_tag"), AuditAction.DELETE)

    def test_create_action_inference(self):
        """Test that create actions are inferred correctly."""
        self.assertEqual(infer_action_from_tool_name("create_api_key"), AuditAction.CREATE)
        self.assertEqual(infer_action_from_tool_name("add_output"), AuditAction.CREATE)

    def test_update_action_inference(self):
        """Test that update actions are inferred correctly."""
        self.assertEqual(infer_action_from_tool_name("set_rule"), AuditAction.UPDATE)
        self.assertEqual(infer_action_from_tool_name("update_config"), AuditAction.UPDATE)

    def test_read_action_inference(self):
        """Test that read actions are inferred correctly."""
        self.assertEqual(infer_action_from_tool_name("get_sensor"), AuditAction.READ)
        self.assertEqual(infer_action_from_tool_name("list_sensors"), AuditAction.READ)
        self.assertEqual(infer_action_from_tool_name("search_hosts"), AuditAction.READ)
        self.assertEqual(infer_action_from_tool_name("query_data"), AuditAction.READ)

    def test_auth_action_inference(self):
        """Test that auth actions are inferred correctly."""
        self.assertEqual(infer_action_from_tool_name("authenticate_user"), AuditAction.AUTH)
        self.assertEqual(infer_action_from_tool_name("login"), AuditAction.AUTH)
        self.assertEqual(infer_action_from_tool_name("generate_token"), AuditAction.AUTH)

    def test_default_action_inference(self):
        """Test that unknown actions default to EXECUTE."""
        self.assertEqual(infer_action_from_tool_name("process_data"), AuditAction.EXECUTE)
        self.assertEqual(infer_action_from_tool_name("unknown_function"), AuditAction.EXECUTE)


class TestAuditDecorator(unittest.TestCase):
    """Test the audit_log decorator."""

    def setUp(self):
        """Set up test fixtures."""
        os.environ["AUDIT_LOG_ENABLED"] = "true"
        os.environ["AUDIT_LOG_LEVEL"] = "LOW"
        os.environ["AUDIT_LOG_INCLUDE_LOW"] = "true"

    def test_decorator_logs_function_call(self):
        """Test that the decorator logs function execution."""
        @audit_log(severity=AuditSeverity.HIGH, action=AuditAction.CREATE)
        def test_function(param1, param2):
            return {"result": "success"}

        with patch('sys.stdout', new=StringIO()) as fake_out:
            result = test_function("value1", "value2")

            output = fake_out.getvalue()

            # Should have two audit events: start and completion
            audit_lines = [line for line in output.split('\n') if line.startswith('AUDIT:')]
            self.assertEqual(len(audit_lines), 2)

            # Check start event
            start_event = json.loads(audit_lines[0].replace('AUDIT: ', ''))
            self.assertEqual(start_event["event_type"], "test_function")
            self.assertEqual(start_event["status"], "started")

            # Check completion event
            completion_event = json.loads(audit_lines[1].replace('AUDIT: ', ''))
            self.assertEqual(completion_event["event_type"], "test_function")
            self.assertEqual(completion_event["status"], "success")
            self.assertIn("duration_ms", completion_event)

    def test_decorator_logs_failures(self):
        """Test that the decorator logs exceptions."""
        @audit_log(severity=AuditSeverity.CRITICAL, action=AuditAction.DELETE)
        def failing_function():
            raise ValueError("Test error")

        with patch('sys.stdout', new=StringIO()) as fake_out:
            with self.assertRaises(ValueError):
                failing_function()

            output = fake_out.getvalue()
            audit_lines = [line for line in output.split('\n') if line.startswith('AUDIT:')]

            # Should have start and failure events
            self.assertGreaterEqual(len(audit_lines), 2)

            # Check failure event
            failure_event = json.loads(audit_lines[-1].replace('AUDIT: ', ''))
            self.assertEqual(failure_event["status"], "failure")
            self.assertEqual(failure_event["error_message"], "ValueError")
            self.assertIn("duration_ms", failure_event)

    def test_decorator_does_not_log_parameters(self):
        """Test that the decorator never logs function parameters."""
        @audit_log(severity=AuditSeverity.HIGH, action=AuditAction.CREATE)
        def function_with_sensitive_params(api_key, secret, password):
            return {"success": True}

        with patch('sys.stdout', new=StringIO()) as fake_out:
            result = function_with_sensitive_params(
                api_key="secret123",
                secret="topsecret",
                password="password123"
            )

            output = fake_out.getvalue()

            # Verify no sensitive data is in the output
            self.assertNotIn("secret123", output)
            self.assertNotIn("topsecret", output)
            self.assertNotIn("password123", output)
            self.assertNotIn("api_key", output)
            self.assertNotIn("secret", output)
            self.assertNotIn("password", output)

    def test_decorator_does_not_log_response(self):
        """Test that the decorator never logs function responses."""
        @audit_log(severity=AuditSeverity.HIGH, action=AuditAction.READ)
        def function_returning_sensitive_data():
            return {
                "api_key": "sensitive_key_123",
                "secret_token": "ultra_secret_token",
                "user_data": {"password": "user_password"}
            }

        with patch('sys.stdout', new=StringIO()) as fake_out:
            result = function_returning_sensitive_data()

            output = fake_out.getvalue()

            # Verify no sensitive response data is in the output
            self.assertNotIn("sensitive_key_123", output)
            self.assertNotIn("ultra_secret_token", output)
            self.assertNotIn("user_password", output)


class TestPerformance(unittest.TestCase):
    """Test performance characteristics of audit logging."""

    def setUp(self):
        """Set up test fixtures."""
        os.environ["AUDIT_LOG_ENABLED"] = "true"
        os.environ["AUDIT_LOG_LEVEL"] = "MEDIUM"

    def test_minimal_overhead(self):
        """Test that audit logging adds minimal overhead."""
        @audit_log(severity=AuditSeverity.MEDIUM, action=AuditAction.EXECUTE)
        def fast_function():
            return "result"

        # Measure time with audit logging
        with patch('sys.stdout', new=StringIO()):
            start = time.time()
            for _ in range(100):
                fast_function()
            with_audit = time.time() - start

        # The overhead should be very small (less than 10ms per call on average)
        avg_overhead = (with_audit / 100) * 1000  # Convert to ms
        self.assertLess(avg_overhead, 10, f"Average overhead {avg_overhead}ms exceeds 10ms threshold")


class TestGlobalLogger(unittest.TestCase):
    """Test the global logger instance."""

    def test_get_audit_logger_returns_singleton(self):
        """Test that get_audit_logger returns the same instance."""
        logger1 = get_audit_logger()
        logger2 = get_audit_logger()
        self.assertIs(logger1, logger2)


if __name__ == "__main__":
    unittest.main()
