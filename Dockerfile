# Use the official Python slim image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Set the working directory
WORKDIR /app

# Install system dependencies including git
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Clone and install MCP from the official GitHub repository
RUN git clone https://github.com/modelcontextprotocol/python-sdk.git /tmp/python-sdk \
    && cd /tmp/python-sdk \
    && pip install --no-cache-dir . \
    && cd /app \
    && rm -rf /tmp/python-sdk \
    && apt-get purge -y git \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && python -c "import mcp; print('MCP package imported successfully')"

# Copy the application code and prompts
COPY server.py .
COPY prompts/ ./prompts/

# Copy OAuth modules (optional, enabled via MCP_OAUTH_ENABLED env var)
# SECURITY: Include rate_limiter.py and token_encryption.py for OAuth security features
COPY oauth_*.py firebase_auth_bridge.py rate_limiter.py token_encryption.py ./

# Expose the application port
EXPOSE 8080
ENV PORT=8080

# Start the server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--loop", "asyncio", "--log-level", "debug", "--limit-concurrency", "1000", "--limit-max-requests", "10000"]
