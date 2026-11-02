import hashlib
import secrets
from typing import Optional
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Query, WebSocket, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.agent import Agent


def _extract_bearer_token(authorization: Optional[str], x_api_key: Optional[str] = None) -> Optional[str]:
    """Extracts a bearer token from Authorization header or X-API-Key header."""
    if authorization:
        scheme, _, param = authorization.partition(" ")
        if scheme.lower() == "bearer" and param.strip():
            return param.strip()
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    return None


async def verify_operator_token(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> str:
    """
    Constant-time verification of the operator administrative bearer token
    for REST control-plane endpoints.
    """
    candidate = _extract_bearer_token(authorization, x_api_key)
    if not candidate or not secrets.compare_digest(candidate, settings.ADMIN_API_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing operator authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return candidate


def verify_operator_ws_credentials(
    websocket: WebSocket,
    query_token: Optional[str] = None,
) -> bool:
    """
    Verifies operator WebSocket handshake credentials from either the
    Authorization header, X-API-Key header, or ?token= query parameter.
    """
    auth_header = websocket.headers.get("authorization")
    api_key_header = websocket.headers.get("x-api-key")
    candidate = _extract_bearer_token(auth_header, api_key_header) or query_token

    if not candidate:
        return False

    return secrets.compare_digest(candidate, settings.ADMIN_API_TOKEN)


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
