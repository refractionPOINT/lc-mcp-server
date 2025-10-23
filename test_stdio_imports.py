#!/usr/bin/env python3
"""
Test that server.py can be imported in STDIO mode without starlette installed.
This simulates the environment when starlette is not available.
"""

import sys
import os

# Set STDIO mode
os.environ["PUBLIC_MODE"] = "false"
os.environ["MCP_PROFILE"] = "all"

# Hide starlette from imports to simulate it not being installed
original_import = __builtins__.__import__

def mock_import(name, *args, **kwargs):
    if name.startswith('starlette'):
        raise ModuleNotFoundError(f"No module named '{name}' (simulated)")
    return original_import(name, *args, **kwargs)

__builtins__.__import__ = mock_import

try:
    # Try to import server - this should work even without starlette in STDIO mode
    print("Testing import of server.py in STDIO mode without starlette...")

    # Mock other dependencies
    class MockManager:
        pass

    class MockSensor:
        pass

    sys.modules['limacharlie'] = type(sys)('limacharlie')
    sys.modules['limacharlie'].Manager = MockManager
    sys.modules['limacharlie'].Sensor = MockSensor
    sys.modules['limacharlie.Replay'] = type(sys)('limacharlie.Replay')

    sys.modules['google'] = type(sys)('google')
    sys.modules['google.genai'] = type(sys)('google.genai')
    sys.modules['google.genai'].types = type(sys)('google.genai.types')
    sys.modules['google.cloud'] = type(sys)('google.cloud')
    sys.modules['google.cloud.storage'] = type(sys)('google.cloud.storage')

    sys.modules['mcp'] = type(sys)('mcp')
    sys.modules['mcp.server'] = type(sys)('mcp.server')
    sys.modules['mcp.server.fastmcp'] = type(sys)('mcp.server.fastmcp')
    sys.modules['mcp.server.fastmcp'].FastMCP = lambda *args, **kwargs: None
    sys.modules['mcp.server.fastmcp.server'] = type(sys)('mcp.server.fastmcp.server')

    class MockContext:
        pass
    sys.modules['mcp.server.fastmcp.server'].Context = MockContext

    # Mock yaml
    sys.modules['yaml'] = type(sys)('yaml')

    # Now try the actual import
    import server

    print("✓ Success! server.py can be imported in STDIO mode without starlette")
    print(f"✓ PUBLIC_MODE = {server.PUBLIC_MODE}")
    print(f"✓ HTTPException = {server.HTTPException}")
    print(f"✓ Request = {server.Request}")

    if server.PUBLIC_MODE:
        print("❌ ERROR: PUBLIC_MODE should be False in STDIO mode")
        sys.exit(1)

    if server.HTTPException is not None:
        print("❌ ERROR: HTTPException should be None in STDIO mode")
        sys.exit(1)

    if server.Request is not None:
        print("❌ ERROR: Request should be None in STDIO mode")
        sys.exit(1)

    print("\n✅ All checks passed! STDIO mode works without starlette installed.")
    sys.exit(0)

except ModuleNotFoundError as e:
    if 'starlette' in str(e):
        print(f"❌ FAILED: server.py still tries to import starlette in STDIO mode")
        print(f"   Error: {e}")
        sys.exit(1)
    else:
        print(f"❌ FAILED: Missing other dependency: {e}")
        sys.exit(1)
except Exception as e:
    print(f"❌ FAILED: Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
