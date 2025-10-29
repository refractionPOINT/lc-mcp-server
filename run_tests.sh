#!/bin/bash
# Run all tests with proper isolation to avoid module import conflicts

set -e

echo "Running test suite with proper isolation..."
echo "==========================================="
echo

# Group 1: OAuth, nested calls, and STDIO tests (can run together)
echo "Group 1: OAuth, nested calls, and STDIO import tests"
python3 -m pytest test_nested_oid_calls.py test_oauth_integration.py test_stdio_imports.py -v --tb=short
echo

# Group 2: HTTP server tests (need isolation due to PUBLIC_MODE=true)
echo "Group 2: HTTP server tests"
python3 -m pytest test_server.py -v --tb=short
echo

# Group 3: UID mode tests (need isolation due to UID_MODE configuration)
echo "Group 3: UID mode tests"
python3 -m pytest test_uid_mode.py -v --tb=short
echo

echo "==========================================="
echo "All test groups completed successfully!"
