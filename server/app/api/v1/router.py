from fastapi import APIRouter

from app.api.v1.endpoints import health, organizations, sites, tokens, agents

api_v1_router = APIRouter()

# Aggregate endpoint routers
api_v1_router.include_router(
    health.router,
    tags=["System Diagnostics"],
)

# Multi-Tenant Organizations Management
api_v1_router.include_router(
    organizations.router,
    prefix="/organizations",
    tags=["Organizations"],
)

# Physical & Logical Sites Management
api_v1_router.include_router(
    sites.router,
    prefix="/sites",
    tags=["Sites"],
)

# Agent Enrollment Tokens Management
api_v1_router.include_router(
    tokens.router,
    prefix="/tokens",
    tags=["Enrollment Tokens"],
)

# Managed Endpoint Agents
api_v1_router.include_router(
    agents.router,
    prefix="/agents",
    tags=["Agents"],
)