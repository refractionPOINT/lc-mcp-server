# Use the official Python slim image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    POETRY_VERSION=2.2.1 \
    POETRY_HOME=/opt/poetry \
    POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=false \
    POETRY_VIRTUALENVS_CREATE=false

# Add Poetry to PATH
ENV PATH="$POETRY_HOME/bin:$PATH"

# Set the working directory
WORKDIR /app

# Install system dependencies including curl and git for Poetry installation
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry with pinned version for reproducibility and security
# Download installer, verify checksum, then execute
# Checksum verified on 2025-10-14
# To update: curl -sSL https://install.python-poetry.org -o install-poetry.py && sha256sum install-poetry.py
RUN curl -sSL https://install.python-poetry.org -o install-poetry.py && \
    echo "963d56703976ce9cdc6ff460c44a4f8fbad64c110dc447b86eeabb4a47ec2160  install-poetry.py" | sha256sum -c - && \
    POETRY_VERSION=$POETRY_VERSION python3 install-poetry.py && \
    rm install-poetry.py && \
    poetry --version

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install dependencies using Poetry (no dev dependencies)
RUN poetry install --without dev --no-root

# Remove build dependencies to reduce image size
RUN apt-get purge -y curl build-essential && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy the application code and prompts
COPY server.py .
COPY prompts/ ./prompts/

# Expose the application port
EXPOSE 8080
ENV PORT=8080

# Start the server
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--loop", "asyncio", "--log-level", "debug", "--limit-concurrency", "1000", "--limit-max-requests", "10000"]
