from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_production_health_endpoint():
    """
    Verifies that GET /api/v1/health responds with 200 OK and confirms
    both PostgreSQL and Redis liveness for container health checks.
    """
    with TestClient(app) as client:
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["database"] == "connected"
        assert body["redis"] == "connected"


def test_dockerfile_and_compose_security_and_healthchecks():
    """
    Validates Day 47 production Dockerfile and docker-compose.yml hardening:
    1. Multi-stage builds (`AS builder`, `AS runtime`) across root, server, and frontend Dockerfiles.
    2. Non-root user execution (`USER rmmuser:rmmgroup`, `USER nginx`) and `HEALTHCHECK` directives.
    3. `docker-compose.yml` defines health checks and `condition: service_healthy` dependencies
       for `postgres`, `redis`, `server`, and `frontend`.
    4. Environment security: fail-fast required secrets (`:?`), localhost-bound ports (`127.0.0.1:`),
       `no-new-privileges:true`, `cap_drop`, and `.dockerignore` secret exclusions.
    """
    root_dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    server_dockerfile = (PROJECT_ROOT / "server" / "Dockerfile").read_text(encoding="utf-8")
    frontend_dockerfile = (PROJECT_ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    compose_content = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    dockerignore_content = (PROJECT_ROOT / ".dockerignore").read_text(encoding="utf-8")

    # 1. Multi-stage & non-root checks in Dockerfiles
    for df in (root_dockerfile, server_dockerfile):
        assert "AS builder" in df
        assert "AS runtime" in df
        assert "USER rmmuser:rmmgroup" in df
        assert "HEALTHCHECK" in df
        assert "/api/v1/health" in df

    assert "AS builder" in frontend_dockerfile
    assert "AS runtime" in frontend_dockerfile
    assert "USER nginx" in frontend_dockerfile
    assert "HEALTHCHECK" in frontend_dockerfile

    # 2. docker-compose.yml services, healthchecks, and environment security
    for svc in ("postgres:", "redis:", "server:", "frontend:"):
        assert svc in compose_content

    assert "condition: service_healthy" in compose_content
    assert "no-new-privileges:true" in compose_content
    assert "cap_drop:" in compose_content
    assert "read_only: true" in compose_content
    assert "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?" in compose_content
    assert "ADMIN_API_TOKEN: ${ADMIN_API_TOKEN:?" in compose_content
    assert '127.0.0.1:${SERVER_PORT:-8000}:8000' in compose_content

    # 3. .dockerignore prevents baking secrets or local virtualenvs into images
    assert ".env" in dockerignore_content
    assert ".keys/" in dockerignore_content
