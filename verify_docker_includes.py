#!/usr/bin/env python3
"""
Verification script to ensure all required Python modules can be imported.
This script should be run inside the Docker container to validate the build.

Usage:
    docker build -t lc-mcp-server .
    docker run --rm lc-mcp-server python verify_docker_includes.py
"""

import sys
import importlib.util

def check_module(module_name: str) -> bool:
    """Check if a module can be imported."""
    try:
        spec = importlib.util.find_spec(module_name)
        if spec is None:
            print(f"❌ FAIL: Module '{module_name}' not found")
            return False
        else:
            # Try to actually import it
            __import__(module_name)
            print(f"✓ PASS: Module '{module_name}' found and imported successfully")
            return True
    except Exception as e:
        print(f"❌ FAIL: Module '{module_name}' import error: {e}")
        return False

def main():
    """Verify all required modules are available."""
    print("Verifying Docker container includes all required Python modules...")
    print("-" * 70)

    required_modules = [
        # Core modules
        "server",

        # OAuth modules
        "oauth_endpoints",
        "oauth_state_manager",
        "oauth_token_manager",
        "oauth_metadata",
        "firebase_auth_bridge",

        # SECURITY FIX: New modules from issue #1, #2, #4
        "rate_limiter",
        "token_encryption",
    ]

    results = []
    for module in required_modules:
        results.append(check_module(module))

    print("-" * 70)

    if all(results):
        print(f"\n✓ SUCCESS: All {len(required_modules)} required modules are available")
        return 0
    else:
        failed_count = results.count(False)
        print(f"\n❌ FAILURE: {failed_count}/{len(required_modules)} modules failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
