# Database Engine & Session Management

## Overview
Database connectivity and session lifecycle management using SQLAlchemy 2.0 and asyncpg.

## Interface
- base.py:Base
- session.py:DATABASE_URL
- session.py:engine
- session.py:async_session_factory
- session.py:get_db

## Invariants
- Database sessions are strictly asynchronous (AsyncSession) with expire_on_commit disabled [session.py:async_session_factory]
- Async engine uses pool pre-ping to detect and recycle stale or dropped database connections [session.py:engine]

## Side Effects
- Initializes and manages a pooled connection pool to PostgreSQL via asyncpg [session.py:engine]

## Verification
- Run: `cd server && pytest`
