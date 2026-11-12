# FastAPI Core Application Package

## Overview
Core application factory, ASGI entry point, and lifespan coordinator for Tactical RMM control plane.

## Subdirectories & Boundaries
- **[api](./api/README.md)**: API routing tree partitioning versions and endpoints
- **[core](./core/README.md)**: Security, cryptography, RBAC enforcement, audit logging, and WebSocket manager
- **[db](./db/README.md)**: Asynchronous PostgreSQL database session and engine pool
- **[models](./models/README.md)**: SQLAlchemy ORM models for tenants, agents, scripts, and immutable audit logs
- **[schemas](./schemas/README.md)**: Pydantic v2 data transfer objects and validation contracts
- **[services](./services/README.md)**: Heartbeat watchdog worker and behavioral alert engine

## Verification
- Run: `cd server && pytest`
