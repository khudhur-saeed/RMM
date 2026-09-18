import hashlib
import logging
import secrets
from uuid import UUID

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from app.core.ws_manager import ws_manager
from app.db.session import async_session_factory
from app.models.agent import Agent

logger = logging.getLogger("rmm.websocket")

router = APIRouter()


async def authenticate_agent_handshake(agent_id: UUID, token: str) -> bool:
    """
    Validates agent authenticity during the initial HTTP handshake.
    Computes SHA-256 digest and performs constant-time comparison against DB hash.
    """
    if not token:
        return False

    computed_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    async with async_session_factory() as session:
        stmt = select(Agent.api_key_hash).where(Agent.id == agent_id)
        result = await session.execute(stmt)
        stored_hash = result.scalar_one_or_none()

        if not stored_hash:
            logger.warning("WS Auth Failed: Agent [%s] not found.", agent_id)
            return False

        # Constant-time comparison defends against timing attacks
        is_valid = secrets.compare_digest(computed_hash, stored_hash)
        if not is_valid:
            logger.warning("WS Auth Failed: Invalid API key hash for Agent [%s].", agent_id)
            return False

        return True


@router.websocket("/agent/{agent_id}")
async def agent_websocket_endpoint(
    websocket: WebSocket,
    agent_id: UUID,
    token: str = Query(..., description="Plaintext Agent API Key for handshake authentication"),
):
    """
    Secure full-duplex WebSocket endpoint for enrolled agents.
    Enforces pre-upgrade validation before accepting the connection.
    """
    # 1. Pre-Accept Authentication Gate
    is_authenticated = await authenticate_agent_handshake(agent_id, token)
    if not is_authenticated:
        # RFC-6455 1008: Policy Violation (Unauthorized handshake)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 2. Upgrade Protocol & Register Active Connection
    await ws_manager.connect(agent_id, websocket)

    # 3. Message Loop & State Maintenance
    try:
        while True:
            # Maintain persistent read channel for incoming telemetry/acknowledgments
            message = await websocket.receive_text()
            logger.debug("Received payload from Agent [%s]: %s", agent_id, message)
    except WebSocketDisconnect:
        logger.info("Agent [%s] closed the WebSocket connection.", agent_id)
    except Exception as exc:
        logger.error("Unexpected socket error on Agent [%s]: %s", agent_id, exc)
    finally:
        # 4. Mandatory cleanup to prevent memory/socket leaks
        ws_manager.disconnect(agent_id)