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

# Check if Poetry is installed and if we should use it
if command -v poetry &> /dev/null; then
    echo "Poetry detected. Using Poetry for dependency management..."
    USE_POETRY=true
else
    echo "Poetry not found. Using pip and venv..."
    USE_POETRY=false
fi

if [ "$USE_POETRY" = true ]; then
    # Install dependencies using Poetry
    echo "Installing dependencies with Poetry..."
    poetry install
else
    # Check if virtual environment exists
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Install dependencies
    echo "Installing dependencies with pip..."
    pip install -r requirements.txt
fi

# Run the server based on PUBLIC_MODE
if [ "${PUBLIC_MODE}" = "true" ]; then
    echo "==================================="
    echo "Starting in HTTP mode (PUBLIC_MODE=true)"
    echo "Server will be available at http://localhost:8000"
    echo "==================================="
    if [ "$USE_POETRY" = true ]; then
        poetry run uvicorn server:app --host 0.0.0.0 --port 8000 --reload --log-level debug
    else
        uvicorn server:app --host 0.0.0.0 --port 8000 --reload --log-level debug
    fi
else
    echo "==================================="
    echo "Starting in STDIO mode (PUBLIC_MODE=false)"
    echo "This mode is for local MCP clients like Claude Desktop or Claude Code"
    echo "The server will communicate through stdin/stdout"
    echo "==================================="
    if [ "$USE_POETRY" = true ]; then
        poetry run python server.py
    else
        python server.py
    fi
fi
