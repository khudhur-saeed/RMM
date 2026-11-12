# ORM Domain Models

## Overview
SQLAlchemy ORM models defining multi-tenant entities, endpoint agents, security credentials, scripts, and immutable audit logs.

## Interface
- agent.py:Agent
- audit_log.py:AuditLog
- audit_log.py:AuditLogImmutabilityError
- organization.py:Organization
- script.py:Script
- site.py:Site
- software.py:InstalledSoftware
- token.py:EnrollmentToken
- user.py:User
- user.py:Role
- user.py:Permission
- user.py:ROLE_PERMISSIONS
- user.py:ROLE_DESCRIPTIONS

## Invariants
- Foreign key constraints enforce ON DELETE CASCADE from Organization to Sites, Agents, and Tokens [organization.py:Organization]
- AuditLog table disallows SQL UPDATE and DELETE operations via ORM event listeners [audit_log.py:AuditLog]
- Enrollment tokens enforce unique plaintext strings and expire after valid_until timestamp [token.py:EnrollmentToken]

## Side Effects
- Registers table schemas, indexes, and relationship listeners in Base.metadata [models/__init__.py]

## Verification
- Run: `cd server && pytest`
