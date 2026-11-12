# Core Security, Cryptography & WebSocket Infrastructure

## Overview
Security, cryptography, RBAC enforcement, audit logging, configuration, and WebSocket connection infrastructure.

## Interface
- audit.py:AuditLogMiddleware
- audit.py:record_audit_log
- audit.py:compute_output_hash
- config.py:Settings
- config.py:settings
- crypto.py:Ed25519KeyPair
- crypto.py:SigningKeyManager
- crypto.py:signing_key_manager
- crypto.py:get_signing_keypair
- crypto.py:sign_payload
- crypto.py:verify_signature
- crypto.py:sign_task_dispatch
- crypto.py:compute_task_digest
- crypto.py:compute_payload_digest
- crypto.py:build_signed_term_in_frame
- crypto.py:load_public_key
- rbac.py:Principal
- rbac.py:RBACMiddleware
- rbac.py:require_permissions
- rbac.py:require_roles
- rbac.py:ensure_org_access
- rbac.py:ensure_site_access
- rbac.py:ensure_agent_access
- rbac.py:extract_bearer_token
- rbac.py:resolve_principal_from_token
- rbac.py:hash_api_token
- rbac.py:generate_user_api_token
- rbac.py:authenticate_ws_operator
- rbac.py:verify_ws_agent_access
- rbac.py:verify_ws_dispatch_permission
- rbac.py:get_current_principal
- security.py:verify_agent_api_key
- security.py:generate_agent_api_key
- ws_manager.py:ConnectionManager
- ws_manager.py:ws_manager

## Invariants
- Private signing keys are saved with 0600 file permissions and never exposed via public endpoints [crypto.py:SigningKeyManager]
- Audit log entries are immutable once written; updates and deletes trigger exceptions [audit.py:AuditLogMiddleware]
- Operator API tokens are stored only as SHA-256 hashes and compared in constant time [rbac.py:hash_api_token]
- Agent WebSocket connections must verify presence against Redis state store with TTL [ws_manager.py:ConnectionManager]

## Side Effects
- Reads and writes Ed25519 private/public key files in .keys directory [crypto.py:SigningKeyManager]
- Establishes asynchronous Redis Pub/Sub channels and sets agent presence keys [ws_manager.py:ConnectionManager]
- Inserts audit log records into PostgreSQL on mutating HTTP requests [audit.py:record_audit_log]

## Verification
- Run: `cd server && pytest tests/test_crypto_keys.py tests/test_audit_logs.py tests/test_ws_redis_direct.py`
