# Build stage
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /build

# Enable automatic Go toolchain downloading for dependency requirements
ENV GOTOOLCHAIN=auto

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 for static binary compatible with distroless
# -ldflags="-w -s" to strip debug info and reduce binary size
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')" \
    -a -installsuffix cgo \
    -o /build/lc-mcp-server \
    ./cmd/server

# Run tests to ensure binary is valid
RUN CGO_ENABLED=0 go test -v ./...

# Runtime stage - distroless for minimal attack surface
FROM gcr.io/distroless/static-debian12:nonroot

# Copy CA certificates from builder for HTTPS connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data for time-related functions
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary from builder
COPY --from=builder /build/lc-mcp-server /app/lc-mcp-server

# Set working directory
WORKDIR /app

# Distroless runs as nonroot user (uid=65532) by default
# No need to explicitly set USER as it's built into the image

# Environment variables
ENV MCP_MODE=stdio \
    MCP_PROFILE=all \
    LOG_LEVEL=info \
    SDK_CACHE_TTL=5m \
    PORT=8080 \
    HTTP_PORT=8080 \
    MCP_SERVER_URL=http://localhost:8080 \
    REDIS_ADDRESS=localhost:6379 \
    REDIS_DB=0 \
    FIREBASE_API_KEY=AIzaSyB5VyO6qS-XlnVD3zOIuEVNBD5JFn22_1w

# Health check metadata (Cloud Run will use this port)
EXPOSE 8080

# Entrypoint
ENTRYPOINT ["/app/lc-mcp-server"]

# Labels for container metadata
LABEL org.opencontainers.image.source="https://github.com/refractionPOINT/lc-mcp-server" \
      org.opencontainers.image.description="LimaCharlie MCP Server - Go Implementation" \
      org.opencontainers.image.licenses="Apache-2.0" \
      maintainer="refractionPOINT"
