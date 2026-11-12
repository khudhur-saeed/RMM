# Control Plane Server Subsystem

## Overview
Subtree root for the Tactical RMM Python FastAPI server, Docker containerization, and database migrations.

## Subdirectories & Boundaries
- **[alembic](./alembic/README.md)**: Alembic database migration environment for PostgreSQL DDL schemas
- **[app](./app/README.md)**: Core FastAPI application factory, API routers, ORM models, and background workers

## Verification
- Run: `cd server && pytest`
