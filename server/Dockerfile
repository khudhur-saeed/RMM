# syntax=docker/dockerfile:1

# ==============================================================================
# Stage 1: Dependency Builder
# ==============================================================================
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# ==============================================================================
# Stage 2: Hardened Non-Root Production Runtime
# ==============================================================================
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:$PATH" \
    SIGNING_KEY_DIR="/app/.keys"

WORKDIR /app

# Create dedicated unprivileged system group and user (UID/GID 10001)
RUN groupadd --gid 10001 rmmgroup && \
    useradd --uid 10001 --gid rmmgroup --shell /usr/sbin/nologin --no-create-home rmmuser && \
    mkdir -p /app/.keys && \
    chown -R rmmuser:rmmgroup /app && \
    chmod 0700 /app/.keys

# Copy isolated virtualenv from builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy application source, Alembic migrations, and entrypoint
COPY --chown=rmmuser:rmmgroup alembic.ini ./
COPY --chown=rmmuser:rmmgroup alembic ./alembic
COPY --chown=rmmuser:rmmgroup app ./app
COPY --chown=rmmuser:rmmgroup entrypoint.sh /app/entrypoint.sh
RUN chmod 0755 /app/entrypoint.sh

# Drop root privileges
USER rmmuser:rmmgroup

EXPOSE 8000

# Liveness & PostgreSQL connectivity healthcheck using Python stdlib (no curl/wget needed)
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
    CMD ["python", "-c", "import urllib.request, sys; resp = urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=4); sys.exit(0 if resp.status == 200 else 1)"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log"]
