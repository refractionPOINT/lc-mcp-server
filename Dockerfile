# Use the official Go image
FROM golang:latest

# Set environment variables
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    PORT=8080

# Set the working directory
WORKDIR /app

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the application code
COPY . .

# Build the application
RUN go build -o lc-mcp-server ./cmd/server

# Expose the application port
EXPOSE 8080
ENV PORT=8080

# Start the server
CMD ["/app/lc-mcp-server"]
