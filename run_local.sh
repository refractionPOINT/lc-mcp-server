#!/bin/bash
# Local development server startup script

echo "Starting LimaCharlie MCP Server..."
echo "Make sure you have set the required environment variables:"
echo "  - GOOGLE_API_KEY (for Gemini API access)"
echo "  - PUBLIC_MODE (true for public deployment, false for local - default: false)"
echo "  - GCS_BUCKET_NAME (optional, for large result storage)"
echo "  - GCS_SIGNER_SERVICE_ACCOUNT (optional, for GCS URL signing)"
echo ""

# Set default PUBLIC_MODE if not set
PUBLIC_MODE=${PUBLIC_MODE:-false}
echo "Current mode: PUBLIC_MODE=${PUBLIC_MODE}"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Install MCP from the specific branch
echo "Installing MCP SDK..."
if [ ! -d "/tmp/python-sdk" ]; then
    git clone --branch ylassoued/feat-request https://github.com/ylassoued/python-sdk.git /tmp/python-sdk
    cd /tmp/python-sdk
    git reset --hard a0d0ee5e2557b581a17261e032b89429876f6492
    pip install .
    cd -
fi

# Run the server based on PUBLIC_MODE
if [ "${PUBLIC_MODE}" = "true" ]; then
    echo "==================================="
    echo "Starting in HTTP mode (PUBLIC_MODE=true)"
    echo "Server will be available at http://localhost:8000"
    echo "==================================="
    uvicorn server:app --host 0.0.0.0 --port 8000 --reload --log-level debug
else
    echo "==================================="
    echo "Starting in STDIO mode (PUBLIC_MODE=false)"
    echo "This mode is for local MCP clients like Claude Desktop or Claude Code"
    echo "The server will communicate through stdin/stdout"
    echo "==================================="
    python server.py
fi