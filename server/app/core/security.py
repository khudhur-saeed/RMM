import hashlib
import secrets
from typing import Optional
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, WebSocket, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import (
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
    Permission,
    Principal,
    RBACMiddleware,
    Role,
    authenticate_ws_operator,
    ensure_agent_access,
    ensure_org_access,
    ensure_site_access,
    extract_bearer_token,
    generate_user_api_token,
    get_current_principal,
    hash_api_token,
    require_permissions,
    require_roles,
    resolve_principal_from_token,
    verify_ws_agent_access,
    verify_ws_dispatch_permission,
)
from app.db.session import get_db
from app.models.agent import Agent


def _extract_bearer_token(
    authorization: Optional[str],
    x_api_key: Optional[str] = None,
) -> Optional[str]:
    """Extracts a bearer token from Authorization header or X-API-Key header."""
    return extract_bearer_token(authorization, x_api_key)


async def verify_operator_token(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> str:
    """
    Verifies operator authentication credentials (bootstrap token or RBAC User token)
    for REST control-plane endpoints and populates `request.state.principal`.
    """
    candidate = _extract_bearer_token(authorization, x_api_key)
    principal = await get_current_principal(
        request=request,
        authorization=authorization,
        x_api_key=x_api_key,
        db=db,
    )
    return candidate or principal.username


def verify_operator_ws_credentials(
    websocket: WebSocket,
    query_token: Optional[str] = None,
) -> bool:
    """
    Synchronous fallback verification of bootstrap operator WebSocket credentials
    from Authorization header, X-API-Key header, or ?token= query parameter.
    """
    auth_header = websocket.headers.get("authorization")
    api_key_header = websocket.headers.get("x-api-key")
    candidate = _extract_bearer_token(auth_header, api_key_header) or query_token

    if not candidate:
        return False

    for bootstrap_tok in (
        settings.ADMIN_API_TOKEN,
        settings.TECHNICIAN_API_TOKEN,
        settings.AUDITOR_API_TOKEN,
    ):
        if bootstrap_tok and secrets.compare_digest(candidate, bootstrap_tok):
            return True
    return False


async def verify_agent_api_key(
    agent_id: UUID,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> Agent:
    """
    Authenticates an endpoint agent via its cryptographic API key hash
    before allowing state-mutating operations such as HTTP heartbeats.
    """
    raw_token = _extract_bearer_token(authorization, x_api_key)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing agent API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    stmt = select(Agent).where(Agent.id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent or not agent.api_key_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent identity or credentials.",
        )

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(token_hash, agent.api_key_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid agent identity or credentials.",
        )

    return agent


__all__ = [
    "Role",
    "Permission",
    "ROLE_PERMISSIONS",
    "ROLE_DESCRIPTIONS",
    "Principal",
    "RBACMiddleware",
    "_extract_bearer_token",
    "extract_bearer_token",
    "hash_api_token",
    "generate_user_api_token",
    "resolve_principal_from_token",
    "get_current_principal",
    "require_permissions",
    "require_roles",
    "ensure_org_access",
    "ensure_site_access",
    "ensure_agent_access",
    "authenticate_ws_operator",
    "verify_ws_agent_access",
    "verify_ws_dispatch_permission",
    "verify_operator_token",
    "verify_operator_ws_credentials",
    "verify_agent_api_key",
]
