from fastapi import APIRouter

from app.api.v1.endpoints import (
    agents,
    audit_logs,
    enroll,
    health,
    keys,
    organizations,
    scripts,
    sites,
    tokens,
    users,
    ws,
)

api_v1_router = APIRouter()

# Control Plane Liveness & Database Connectivity
api_v1_router.include_router(
    health.router,
    tags=["Health"],
)

# Multi-Tenant Core Boundaries
api_v1_router.include_router(
    organizations.router,
    prefix="/organizations",
    tags=["Organizations"],
)
api_v1_router.include_router(
    sites.router,
    prefix="/sites",
    tags=["Sites"],
)
api_v1_router.include_router(
    tokens.router,
    prefix="/tokens",
    tags=["Enrollment Tokens"],
)

# Dedicated Single-Use Agent Enrollment Subsystem
api_v1_router.include_router(
    enroll.router,
    prefix="/enroll",
    tags=["Enrollment"],
)

# Operational Telemetry & Fleet Management
api_v1_router.include_router(
    agents.router,
    prefix="/agents",
    tags=["Agents"],
)

# Script Keystore & Parameterized Task Templates
api_v1_router.include_router(
    scripts.router,
    prefix="/scripts",
    tags=["Script Keystore"],
)

# Ed25519 Code-Signing & Agent Public Key Verification
api_v1_router.include_router(
    keys.router,
    prefix="/keys",
    tags=["Cryptographic Keys"],
)

# Role-Based Access Control (RBAC) Operators & Roles
api_v1_router.include_router(
    users.router,
    prefix="/users",
    tags=["RBAC & Operators"],
)
api_v1_router.include_router(
    users.router,
    prefix="/rbac",
    tags=["RBAC & Operators"],
    include_in_schema=False,
)

# Immutable Security Audit Logs
api_v1_router.include_router(
    audit_logs.router,
    prefix="/audit-logs",
    tags=["Audit Logs"],
)
api_v1_router.include_router(
    audit_logs.router,
    prefix="/audit",
    tags=["Audit Logs"],
    include_in_schema=False,
)

# Real-Time Full-Duplex Command & Telemetry Tunnels
api_v1_router.include_router(
    ws.router,
    prefix="/ws",
    tags=["WebSockets"],
)
