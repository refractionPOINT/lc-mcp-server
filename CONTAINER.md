# Container Deployment Guide

This guide covers building, running, and deploying the LimaCharlie MCP Server using containers.

## Quick Start

### Local Development

```bash
# Build the container
make docker-build

# Run with docker-compose
make docker-compose-up

# Run tests in container
make docker-test
```

## Container Architecture

### Multi-Stage Build

The Dockerfile uses a multi-stage build for optimal security and size:

1. **Builder Stage** (`golang:1.23-alpine`)
   - Compiles Go binary with static linking
   - Runs tests to validate build
   - Creates minimal, optimized binary

2. **Runtime Stage** (`gcr.io/distroless/static-debian12:nonroot`)
   - Distroless base (no shell, no package manager)
   - Runs as non-root user (uid=65532)
   - Only contains compiled binary and runtime dependencies
   - Minimal attack surface

### Security Features

✅ **Distroless Base Image**
- No shell or package manager
- Reduces attack surface by ~99%
- Only contains application and runtime dependencies

✅ **Non-Root User**
- Runs as user `nonroot` (uid=65532, gid=65532)
- Prevents privilege escalation

✅ **Static Binary**
- No dynamic linking (CGO_ENABLED=0)
- No external dependencies
- Works perfectly with distroless

✅ **Read-Only Root Filesystem**
- Application cannot modify itself
- Reduces attack surface

✅ **Security Options**
- `no-new-privileges:true` prevents privilege escalation
- Minimal tmpfs for temporary files

## Building the Container

### Local Build

```bash
# Using Make
make docker-build

# Using Docker directly
docker build -t lc-mcp-server:latest .

# Build with specific tag
docker build -t lc-mcp-server:v1.0.0 .
```

### Build Arguments

The Dockerfile supports the following build arguments:

```bash
docker build \
  --build-arg BUILDKIT_INLINE_CACHE=1 \
  -t lc-mcp-server:latest .
```

## Running the Container

### Docker Run

```bash
# Basic run (stdio mode)
docker run --rm -it \
  -e MCP_MODE=stdio \
  -e MCP_PROFILE=all \
  -e LC_OID=your-org-id \
  -e LC_API_KEY=your-api-key \
  lc-mcp-server:latest

# With OAuth
docker run --rm -it \
  -e MCP_MODE=stdio \
  -e MCP_PROFILE=all \
  -e LC_UID=your-user-id \
  -e LC_JWT=your-jwt-token \
  -e LC_JWT_ISSUER=https://auth.limacharlie.io \
  -e LC_JWT_AUDIENCE=limacharlie-mcp-api \
  -e LC_JWT_PUBLIC_KEY_FILE=/config/public.pem \
  -v $(pwd)/config:/config:ro \
  lc-mcp-server:latest
```

### Docker Compose

```bash
# Start services
docker-compose up --build

# Run in background
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f app
```

### Environment Variables

See [README.md](./README.md) for complete environment variable documentation.

## Google Cloud Platform Deployment

### Prerequisites

```bash
# Install Google Cloud SDK
# https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth login

# Set project
gcloud config set project YOUR_PROJECT_ID

# Enable required APIs
gcloud services enable \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  run.googleapis.com
```

### Artifact Registry Setup

```bash
# Create repository
gcloud artifacts repositories create lc-mcp-server \
  --repository-format=docker \
  --location=us-central1 \
  --description="LimaCharlie MCP Server"

# Configure Docker authentication
gcloud auth configure-docker us-central1-docker.pkg.dev
```

### Build with Cloud Build

```bash
# Build and push to Artifact Registry
gcloud builds submit --config=cloudbuild.yaml

# Build with custom substitutions
gcloud builds submit --config=cloudbuild.yaml \
  --substitutions=_REGION=us-east1,_REPOSITORY=my-repo
```

### Deploy to Cloud Run

#### Option 1: Automatic Deployment

Uncomment the deploy step in `cloudbuild.yaml`:

```yaml
steps:
  # ... build and push steps ...

  # Uncomment this section
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    id: 'deploy'
    entrypoint: 'gcloud'
    args:
      - 'run'
      - 'deploy'
      # ... deployment configuration
```

Then run:
```bash
gcloud builds submit --config=cloudbuild.yaml
```

#### Option 2: Manual Deployment

```bash
# Deploy specific image
gcloud run deploy lc-mcp-server \
  --image=us-central1-docker.pkg.dev/YOUR_PROJECT/lc-mcp-server/lc-mcp-server:abc123 \
  --region=us-central1 \
  --platform=managed \
  --no-allow-unauthenticated \
  --set-env-vars=MCP_MODE=stdio,MCP_PROFILE=all,LOG_LEVEL=info \
  --set-secrets=LC_OID=lc-oid:latest,LC_API_KEY=lc-api-key:latest \
  --memory=512Mi \
  --cpu=1 \
  --min-instances=0 \
  --max-instances=10 \
  --concurrency=80 \
  --timeout=300s
```

#### Option 3: Using Deploy Configuration

```bash
# Deploy to staging
gcloud builds submit --config=cloudbuild-deploy.yaml \
  --substitutions=_IMAGE_TAG=abc123,_ENV=staging

# Deploy to production
gcloud builds submit --config=cloudbuild-deploy.yaml \
  --substitutions=_IMAGE_TAG=abc123,_ENV=production,_MIN_INSTANCES=1,_MAX_INSTANCES=100
```

### Secret Management

Store credentials in Google Secret Manager:

```bash
# Create secrets
echo -n "your-org-id" | gcloud secrets create lc-oid --data-file=-
echo -n "your-api-key" | gcloud secrets create lc-api-key --data-file=-

# For JWT public key
gcloud secrets create lc-jwt-public-key --data-file=public.pem

# Grant access to Cloud Run service account
gcloud secrets add-iam-policy-binding lc-oid \
  --member=serviceAccount:lc-mcp-server@YOUR_PROJECT.iam.gserviceaccount.com \
  --role=roles/secretmanager.secretAccessor
```

## Security Scanning

### Trivy Vulnerability Scanning

```bash
# Install Trivy
# macOS: brew install trivy
# Linux: apt-get install trivy

# Scan image
make docker-scan

# Or directly
trivy image lc-mcp-server:latest

# Scan with severity filter
trivy image --severity HIGH,CRITICAL lc-mcp-server:latest
```

### Cloud Build Vulnerability Scanning

Cloud Build automatically scans images pushed to Artifact Registry.

View scan results:
```bash
# List vulnerabilities
gcloud artifacts docker images list-vulnerabilities \
  us-central1-docker.pkg.dev/YOUR_PROJECT/lc-mcp-server/lc-mcp-server:latest
```

## Image Size Comparison

| Image Type | Size | Description |
|------------|------|-------------|
| Python (alpine) | ~200MB | Python + dependencies |
| Python (slim) | ~400MB | Debian + Python |
| Go (scratch) | ~15MB | Static binary only |
| **Go (distroless)** | **~20MB** | **Static binary + CA certs + tzdata** |

The Go distroless image is **10-20x smaller** than Python images while providing **better security**.

## Performance

### Cold Start Times

| Platform | Cold Start | Notes |
|----------|------------|-------|
| Cloud Run | ~100-200ms | Distroless starts very fast |
| Docker | ~50ms | Local container startup |
| Binary | ~10ms | Direct execution |

### Memory Usage

| Workload | Memory | CPU |
|----------|--------|-----|
| Idle | 10-20MB | <1% |
| Light (10 req/s) | 30-50MB | 5-10% |
| Heavy (100 req/s) | 100-150MB | 30-50% |

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker logs lc-mcp-server

# Interactive debugging (won't work with distroless - use builder stage)
docker run --rm -it --entrypoint=sh golang:1.23-alpine
```

### Build Failures

```bash
# Clear Docker cache
docker builder prune -a

# Build with verbose output
docker build --progress=plain --no-cache -t lc-mcp-server:latest .
```

### Permission Issues

```bash
# Check container is running as nonroot
docker run --rm lc-mcp-server:latest id

# Should output: uid=65532(nonroot) gid=65532(nonroot) groups=65532(nonroot)
```

### Cloud Run Issues

```bash
# View logs
gcloud run services logs read lc-mcp-server --region=us-central1

# Describe service
gcloud run services describe lc-mcp-server --region=us-central1

# List revisions
gcloud run revisions list --service=lc-mcp-server --region=us-central1
```

## Best Practices

### Production Deployment Checklist

- [ ] Use specific image tags (not `latest`)
- [ ] Store secrets in Secret Manager
- [ ] Enable Cloud Run authentication
- [ ] Set appropriate resource limits
- [ ] Configure min/max instances based on load
- [ ] Enable Cloud Logging and Monitoring
- [ ] Set up health checks
- [ ] Configure custom domain (if needed)
- [ ] Enable VPC connector (for private access)
- [ ] Set up Cloud Armor (for DDoS protection)

### Security Checklist

- [ ] Container runs as non-root user ✅
- [ ] Read-only root filesystem ✅
- [ ] No shell in container ✅
- [ ] Minimal base image (distroless) ✅
- [ ] Regular vulnerability scanning
- [ ] Secrets via Secret Manager (not env vars)
- [ ] Network policies configured
- [ ] HTTPS only
- [ ] Authentication required
- [ ] Rate limiting enabled

### Monitoring

```bash
# Cloud Run metrics
gcloud run services describe lc-mcp-server \
  --region=us-central1 \
  --format='value(status.conditions)'

# View logs with filters
gcloud run services logs read lc-mcp-server \
  --region=us-central1 \
  --filter='severity>=WARNING' \
  --limit=50
```

## References

- [Distroless Container Images](https://github.com/GoogleContainerTools/distroless)
- [Google Cloud Build Documentation](https://cloud.google.com/build/docs)
- [Cloud Run Documentation](https://cloud.google.com/run/docs)
- [Docker Multi-Stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [Go Container Best Practices](https://cloud.google.com/run/docs/tips/go)
