# API v1 Router Group

## Overview
Central versioned routing tree aggregating sub-routers for health checks, multi-tenancy, scripts, keys, RBAC, and WebSocket tunnels.

## Subdirectories & Boundaries
- **[endpoints](./endpoints/README.md)**: REST and WebSocket endpoints for agent lifecycle, keys, scripts, users, and C2 tunnels

## Verification
- Run: `cd server && pytest`
