# ==============================================================================
# CloudGuard IAM & CSPM Analyzer - Production Multi-Stage Dockerfile
# Base: python:3.11-slim for minimal attack surface and small image size
# ==============================================================================

# ----------------- Stage 1: Build Dependencies & Wheels -----------------------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /install

# Install compile-time build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install dependencies into a separate prefix for clean copying
RUN pip install --upgrade pip && \
    pip install --prefix=/install/deps -r requirements.txt

# ----------------- Stage 2: Final Minimal Runtime Image -----------------------
FROM python:3.11-slim AS runner

# Metadata labels for container security and traceability
LABEL maintainer="DevSecOps Engineering Team" \
      org.opencontainers.image.title="CloudGuard IAM & CSPM Analyzer" \
      org.opencontainers.image.description="Cloud Security Posture & IAM Privilege Analyzer with IsolationForest ML" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_THEME_BASE="dark" \
    PATH="/app/.local/bin:/opt/venv/bin:${PATH}" \
    PYTHONPATH="/app:${PYTHONPATH}"

WORKDIR /app

# Install runtime utilities (curl for Kubernetes/Docker health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder stage
COPY --from=builder /install/deps /usr/local

# Create non-root user and group with explicit UID/GID for least privilege
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser && \
    mkdir -p /app/data /app/.streamlit && \
    chown -R appuser:appgroup /app

# Copy application source code and pre-loaded sample datasets
COPY --chown=appuser:appgroup src/ /app/src/
COPY --chown=appuser:appgroup data/ /app/data/
COPY --chown=appuser:appgroup README.md /app/README.md

# Switch to unprivileged security context
USER 10001:10001

EXPOSE 8501

# Healthcheck targeting Streamlit's official internal health probe endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "src/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
