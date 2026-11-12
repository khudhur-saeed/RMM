# API v1 Endpoint Handlers

## Overview
REST and WebSocket endpoints implementing multi-tenant management, agent enrollment, script execution, cryptographic operations, and real-time C2 telemetry.

## Interface
- agents.py:list_agents (GET /api/v1/agents)
- agents.py:get_agent (GET /api/v1/agents/{agent_id})
- agents.py:update_agent (PATCH /api/v1/agents/{agent_id})
- agents.py:delete_agent (DELETE /api/v1/agents/{agent_id})
- agents.py:record_heartbeat (POST /api/v1/agents/{agent_id}/heartbeat)
- agents.py:dispatch_task (POST /api/v1/agents/{agent_id}/tasks)
- agents.py:get_agent_software (GET /api/v1/agents/{agent_id}/software)
- audit_logs.py:list_audit_logs (GET /api/v1/audit-logs)
- audit_logs.py:get_audit_log (GET /api/v1/audit-logs/{log_id})
- download.py:download_agent_binary (GET /api/v1/download/{os_name}/{arch})
- download.py:get_binary_checksum (GET /api/v1/download/checksums/{os_name}/{arch})
- download.py:download_linux_bootstrap_script (GET /api/v1/download/install.sh)
- download.py:download_windows_bootstrap_script (GET /api/v1/download/install.ps1)
- enroll.py:enroll_agent (POST /api/v1/enroll)
- health.py:check_health (GET /api/v1/health)
- keys.py:get_public_verification_key (GET /api/v1/keys/public)
- keys.py:rotate_signing_key (POST /api/v1/keys/rotate)
- keys.py:sign_script_payload (POST /api/v1/keys/sign)
- keys.py:verify_script_signature (POST /api/v1/keys/verify)
- organizations.py:create_organization (POST /api/v1/organizations)
- organizations.py:list_organizations (GET /api/v1/organizations)
- organizations.py:get_organization (GET /api/v1/organizations/{org_id})
- scripts.py:create_script (POST /api/v1/scripts)
- scripts.py:list_scripts (GET /api/v1/scripts)
- scripts.py:get_script (GET /api/v1/scripts/{script_id})
- scripts.py:update_script (PATCH /api/v1/scripts/{script_id})
- scripts.py:delete_script (DELETE /api/v1/scripts/{script_id})
- scripts.py:render_script (POST /api/v1/scripts/{script_id}/render)
- scripts.py:render_and_dispatch_script (POST /api/v1/scripts/{script_id}/render with agent_id)
- sites.py:create_site (POST /api/v1/sites)
- sites.py:list_sites (GET /api/v1/sites)
- sites.py:get_site (GET /api/v1/sites/{site_id})
- tokens.py:create_token (POST /api/v1/tokens)
- tokens.py:list_tokens (GET /api/v1/tokens)
- tokens.py:revoke_enrollment_token (DELETE /api/v1/tokens/{token_id})
- users.py:create_user (POST /api/v1/users)
- users.py:list_users (GET /api/v1/users)
- users.py:get_user (GET /api/v1/users/{user_id})
- users.py:update_user (PATCH /api/v1/users/{user_id})
- users.py:delete_user (DELETE /api/v1/users/{user_id})
- users.py:rotate_user_token (POST /api/v1/users/{user_id}/rotate-token)
- users.py:list_roles (GET /api/v1/users/roles)
- users.py:get_current_operator_profile (GET /api/v1/users/me)
- ws.py:agent_websocket_endpoint (WebSocket /api/v1/ws/agent/{agent_id})
- ws.py:operator_websocket_endpoint (WebSocket /api/v1/ws/operator/{agent_id})

## Invariants
- All mutating operator routes require authenticated principal with matching RBAC permission [rbac.py:require_permissions]
- Single-use enrollment tokens require atomic row-level lock and cannot be re-used once marked used [enroll.py:enroll_agent]
- WebSocket connections require bearer token authentication validated against hashed agent API key in database [ws.py:agent_websocket_endpoint]
- Direct signing of task dispatch or terminal input frames via /keys/sign is explicitly rejected to prevent signature forgery [keys.py:sign_script_payload]

## Side Effects
- Performs ACID CRUD operations on PostgreSQL database via AsyncSession [db/session.py:get_db]
- Emits real-time task frames and buffers terminal output across Redis pub/sub channels [core/ws_manager.py:ConnectionManager]
- Generates, loads, and rotates Ed25519 cryptographic key files on filesystem under SIGNING_KEY_DIR [core/crypto.py:SigningKeyManager]

## Verification
- Run: `cd server && pytest tests/test_crypto_keys.py tests/test_rbac.py`
