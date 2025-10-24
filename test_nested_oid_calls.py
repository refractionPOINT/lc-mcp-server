#!/usr/bin/env python3
"""
Test script to verify nested OID calls and HiveRecord serialization fixes.
"""
import sys
from unittest.mock import Mock, MagicMock, patch
import contextvars

# Import the server module
import server

def test_nested_calls_with_oid():
    """Test that nested wrapped function calls inherit OID from context."""
    print("Testing nested calls with OID context...")

    # Set up UID auth context to simulate UID mode
    server.uid_auth_context_var.set(("test-uid", "test-api-key", "api_key"))

    # Set OID in context (simulating outer wrapper having set it)
    server.current_oid_context_var.set("test-oid-123")

    # Create a mock wrapped function that checks for OID
    def mock_tool(ctx):
        """Mock tool that would normally require OID parameter."""
        return {"result": "success"}

    # Apply the wrapper
    wrapped = server.wrap_tool_for_multi_mode(mock_tool, is_async=False)

    # Mock the Context
    mock_ctx = Mock()

    # Mock SDK creation and other dependencies
    with patch.object(server, 'limacharlie') as mock_lc:
        mock_sdk = MagicMock()
        mock_lc.Manager.return_value = mock_sdk

        # Call wrapped function WITHOUT oid parameter
        # It should use OID from context instead
        try:
            result = wrapped(ctx=mock_ctx)
            print("✓ Nested call succeeded without explicit OID parameter")
            print(f"  Result: {result}")
            return True
        except ValueError as e:
            if "oid' parameter is required" in str(e):
                print("✗ Nested call failed - OID not inherited from context")
                print(f"  Error: {e}")
                return False
            raise

def test_hive_record_serialization():
    """Test that HiveRecord.toJSON() is called in get_rule function."""
    print("\nTesting HiveRecord serialization...")

    # Read the source code and check if .toJSON() is called
    import inspect
    source = inspect.getsource(server.get_rule)

    if 'rule.toJSON()' in source:
        print("✓ get_rule() calls rule.toJSON()")
        print("  Confirmed fix: HiveRecord will be properly serialized")
        return True
    elif 'rule if rule' in source and 'toJSON' not in source:
        print("✗ get_rule() does NOT call rule.toJSON()")
        print("  HiveRecord objects will not be JSON serializable")
        return False
    else:
        print("? Unable to verify - code structure may have changed")
        return False

def main():
    """Run all tests."""
    print("=" * 60)
    print("Testing Nested OID Calls and HiveRecord Serialization Fixes")
    print("=" * 60)

    results = []

    # Test 1: Nested calls with OID context
    results.append(test_nested_calls_with_oid())

    # Test 2: HiveRecord serialization
    results.append(test_hive_record_serialization())

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"Passed: {passed}/{total}")

    if passed == total:
        print("\n✓ All tests passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
