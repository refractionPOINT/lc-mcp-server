#!/usr/bin/env python3
"""
Manual verification script for UID mode functionality.

This script verifies that:
1. Tool signatures include oid parameter
2. Mode detection works correctly
3. Validation logic is correct

Run this to quickly verify the implementation without needing pytest.
"""

import os
import sys
import inspect

# Set up environment
os.environ["PUBLIC_MODE"] = "false"
os.environ["MCP_PROFILE"] = "all"

# Mock dependencies (minimal mocking for verification)
from unittest.mock import MagicMock

sys.modules['limacharlie'] = MagicMock()
sys.modules['limacharlie.Replay'] = MagicMock()
sys.modules['google'] = MagicMock()
sys.modules['google.genai'] = MagicMock()
sys.modules['google.genai.types'] = MagicMock()
sys.modules['google.cloud'] = MagicMock()
sys.modules['google.cloud.storage'] = MagicMock()
sys.modules['google.auth'] = MagicMock()
sys.modules['google.auth.transport'] = MagicMock()
sys.modules['google.auth.transport.requests'] = MagicMock()
sys.modules['mcp'] = MagicMock()
sys.modules['mcp.server'] = MagicMock()
sys.modules['mcp.server.fastmcp'] = MagicMock()
sys.modules['mcp.server.fastmcp.server'] = MagicMock()

# Import server components
from server import (
    wrap_tool_for_multi_mode,
    uid_auth_context_var,
    sdk_context_var,
    get_uid_from_environment,
    validate_oid_parameter
)

def test_signature_modification():
    """Verify that tool signatures are correctly modified"""
    print("Test 1: Verifying signature modification...")

    def sample_tool(param1: str, param2: int, ctx):
        return {"result": "ok"}

    wrapped = wrap_tool_for_multi_mode(sample_tool, is_async=False)
    sig = inspect.signature(wrapped)
    params = list(sig.parameters.keys())

    # Verify oid parameter was added
    assert 'oid' in params, "❌ oid parameter not found in signature"
    assert params[-2] == 'oid', "❌ oid parameter not in correct position"
    assert params[-1] == 'ctx', "❌ ctx parameter not last"

    # Verify oid is optional
    oid_param = sig.parameters['oid']
    assert oid_param.default is None, "❌ oid parameter should default to None"

    print("✓ Signature modification works correctly")
    print(f"  Original params: ['param1', 'param2', 'ctx']")
    print(f"  Wrapped params:  {params}")
    return True

def test_validation_logic():
    """Verify validation logic"""
    print("\nTest 2: Verifying validation logic...")

    # Test UID mode requires oid
    try:
        validate_oid_parameter(None, uid_mode=True, tool_name="test")
        print("❌ Should have raised ValueError for missing oid in UID mode")
        return False
    except ValueError as e:
        if "required in UID mode" not in str(e):
            print(f"❌ Wrong error message: {e}")
            return False

    # Test UID mode accepts oid
    try:
        validate_oid_parameter("test-oid", uid_mode=True, tool_name="test")
    except ValueError:
        print("❌ Should not raise for valid oid in UID mode")
        return False

    # Test normal mode rejects oid
    try:
        validate_oid_parameter("test-oid", uid_mode=False, tool_name="test")
        print("❌ Should have raised ValueError for oid in normal mode")
        return False
    except ValueError as e:
        if "not allowed in normal mode" not in str(e):
            print(f"❌ Wrong error message: {e}")
            return False

    # Test normal mode accepts no oid
    try:
        validate_oid_parameter(None, uid_mode=False, tool_name="test")
    except ValueError:
        print("❌ Should not raise for missing oid in normal mode")
        return False

    print("✓ Validation logic works correctly")
    return True

def test_mode_detection():
    """Verify mode detection"""
    print("\nTest 3: Verifying mode detection...")

    def test_tool(ctx):
        return {"result": "ok"}

    wrapped = wrap_tool_for_multi_mode(test_tool, is_async=False)

    # Test UID mode detection
    uid_auth_context_var.set(("test-uid", "test-api-key"))

    try:
        # Should fail without oid
        try:
            wrapped(ctx=MagicMock())
            print("❌ UID mode should require oid parameter")
            return False
        except ValueError as e:
            if "required in UID mode" not in str(e):
                print(f"❌ Wrong error in UID mode: {e}")
                return False
    finally:
        uid_auth_context_var.set(None)

    # Test normal mode detection
    sdk_context_var.set(MagicMock())

    try:
        # Should fail with oid
        try:
            wrapped(oid="test-oid", ctx=MagicMock())
            print("❌ Normal mode should reject oid parameter")
            return False
        except ValueError as e:
            if "not allowed in normal mode" not in str(e):
                print(f"❌ Wrong error in normal mode: {e}")
                return False
    finally:
        sdk_context_var.set(None)

    print("✓ Mode detection works correctly")
    return True

def test_environment_detection():
    """Verify UID environment detection"""
    print("\nTest 4: Verifying environment detection...")

    # Test LC_UID environment variable
    os.environ["LC_UID"] = "test-uid-from-env"
    uid = get_uid_from_environment()

    if uid != "test-uid-from-env":
        print(f"❌ Failed to get UID from environment: {uid}")
        return False

    del os.environ["LC_UID"]

    print("✓ Environment detection works correctly")
    return True

def main():
    """Run all verification tests"""
    print("=" * 60)
    print("UID Mode Implementation Verification")
    print("=" * 60)

    tests = [
        test_signature_modification,
        test_validation_logic,
        test_mode_detection,
        test_environment_detection
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} raised exception: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("\n✅ All verification tests passed!")
        print("\nUID mode implementation is working correctly:")
        print("  • Tool signatures correctly include optional 'oid' parameter")
        print("  • Mode detection based on uid_auth_context_var works")
        print("  • Validation logic correctly enforces mode requirements")
        print("  • Environment variable detection works")
        return 0
    else:
        print(f"\n❌ {failed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
