# Database Schema Migrations

## Overview
Database schema migration environment configured for asynchronous PostgreSQL migrations with SQLAlchemy 2.0.

## Interface
- env.py:run_migrations_offline
- env.py:do_run_migrations
- env.py:run_async_migrations

## Invariants
- Schema migrations target the declarative metadata defined in Base.metadata from app.models [env.py:target_metadata]
- Database URL is synchronized dynamically from centralized settings [env.py:DATABASE_URL]

## Side Effects
- Executes DDL operations (CREATE, ALTER, DROP tables/indexes/foreign keys) against PostgreSQL [env.py:run_async_migrations]

## Verification
- Run: `cd server && pytest`
