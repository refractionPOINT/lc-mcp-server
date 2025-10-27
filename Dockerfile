# Use the official Python slim image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (includes MCP 1.19.0 from PyPI)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -c "import mcp; print('MCP package imported successfully')"

# Copy the application code and prompts
COPY server.py .
COPY prompts/ ./prompts/

# Copy OAuth modules (optional, enabled via MCP_OAUTH_ENABLED env var)
# SECURITY: Include rate_limiter.py and token_encryption.py for OAuth security features
COPY oauth_*.py firebase_auth_bridge.py rate_limiter.py token_encryption.py ./

# Copy audit logging modules
COPY audit_logger.py audit_decorator.py ./

# Expose the application port
EXPOSE 8080
ENV PORT=8080

# Start the server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--loop", "asyncio", "--log-level", "debug", "--limit-concurrency", "1000", "--limit-max-requests", "10000"]
