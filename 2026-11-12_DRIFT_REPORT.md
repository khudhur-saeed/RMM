# EGM Drift Report (2026-11-12)

This report details the architectural and symbol-level drift analysis performed between the generated EGM contract documentation and the actual implementation in the repository.

---

## README.md (Root Blueprint)

No drift detected.

---

## server/app/api/v1/endpoints/README.md

- **Route Handler Function Names (Resolved)**:
  - Corrected `get_current_user_me` to actual symbol `get_current_operator_profile` (GET `/api/v1/users/me`).
  - Corrected `revoke_token` to actual symbol `revoke_enrollment_token` (DELETE `/api/v1/tokens/{token_id}`).
  - Documented `render_and_dispatch_script` (POST `/api/v1/scripts/{script_id}/render` with `agent_id`).
- **Cross-Package Invariant References**:
  - Invariants cite `[rbac.py:require_permissions]`, `[session.py:get_db]`, `[ws_manager.py:ConnectionManager]`, and `[crypto.py:SigningKeyManager]` from parent packages `app/core/` and `app/db/`.

---

## server/app/core/README.md

- **Symbol Attribution (Resolved)**:
  - Aligned `security.py` symbols to `verify_agent_api_key` and `generate_agent_api_key`. Operator token verification and hashing are consolidated in `rbac.py` (`extract_bearer_token`, `resolve_principal_from_token`, `hash_api_token`).

---

## server/app/models/README.md

No drift detected.

---

## server/app/schemas/README.md

No drift detected.

---

## server/app/services/README.md

No drift detected.

---

## server/app/db/README.md

No drift detected.

---

## server/alembic/README.md

No drift detected.

---

## server/README.md

No drift detected.

---

## frontend/src/components/README.md

No drift detected.

---

## frontend/src/README.md

No drift detected.

---

## frontend/README.md

No drift detected.

---

## scripts/README.md

No drift detected.

---

## agent/cmd/rmmagent/README.md

No drift detected.

---

## agent/internal/crypto/README.md

No drift detected.

---

## agent/internal/client/README.md

No drift detected.

---

## agent/internal/config/README.md

No drift detected.

---

## agent/internal/exec/README.md

No drift detected.

---

## agent/internal/fim/README.md

No drift detected.

---

## agent/internal/inventory/README.md

No drift detected.

---

## agent/internal/netstat/README.md

No drift detected.

---

## agent/internal/process/README.md

No drift detected.

---

## agent/internal/service/README.md

No drift detected.

---

## agent/internal/system/README.md

No drift detected.

---

## agent/internal/telemetry/README.md

No drift detected.

---

## agent/internal/terminal/README.md

No drift detected.

---

## agent/internal/ws/README.md

No drift detected.

---

## agent/internal/authmon/README.md

No drift detected.

---

## agent/internal/eventlog/README.md

No drift detected.
