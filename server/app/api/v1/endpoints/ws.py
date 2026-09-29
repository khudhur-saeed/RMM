import hashlib
import json
import logging
import secrets
from uuid import UUID

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError
from sqlalchemy import select

from app.core.ws_manager import ws_manager
from app.db.session import async_session_factory
from app.models.agent import Agent
from app.schemas.task import TaskExitFrame, TaskStreamFrame

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
    Dispatches commands and demultiplexes live streamed stdout/stderr chunks and task exits.
    """
    # 1. Pre-Accept Authentication Gate
    is_authenticated = await authenticate_agent_handshake(agent_id, token)
    if not is_authenticated:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 2. Upgrade Protocol & Register Active Connection
    await ws_manager.connect(agent_id, websocket)

    # 3. Dedicated Inbound Message Demultiplexer Loop
    try:
        while True:
            raw_message = await websocket.receive_text()

            try:
                envelope = json.loads(raw_message)
                frame_type = envelope.get("type")
            except (json.JSONDecodeError, AttributeError):
                logger.warning("Agent [%s] sent invalid non-JSON framing: %s", agent_id, raw_message[:64])
                continue

            if frame_type == "task_stream":
                try:
                    stream_frame = TaskStreamFrame.model_validate(envelope)
                    # Tactical Log: Outputs streamed chunks live (stdout/stderr)
                    logger.info(
                        "[Task Stream] Agent [%s] Task [%s] [%s]: %s",
                        agent_id,
                        stream_frame.task_id,
                        stream_frame.stream,
                        stream_frame.chunk.rstrip("\r\n"),
                    )
                except ValidationError as val_err:
                    logger.error("TaskStreamFrame schema error from Agent [%s]: %s", agent_id, val_err)

            elif frame_type == "task_exit":
                try:
                    exit_frame = TaskExitFrame.model_validate(envelope)
                    logger.info(
                        "[+] [Task Exit] Agent [%s] Task [%s] completed with code [%d] in [%dms]",
                        agent_id,
                        exit_frame.task_id,
                        exit_frame.exit_code,
                        exit_frame.elapsed_ms,
                    )
                except ValidationError as val_err:
                    logger.error("TaskExitFrame schema error from Agent [%s]: %s", agent_id, val_err)

            elif frame_type == "heartbeat":
                # Extensible heartbeat ingestion
                logger.debug("Heartbeat received from Agent [%s]", agent_id)

            else:
                logger.warning("Agent [%s] dispatched unhandled frame type: %s", agent_id, frame_type)

    except WebSocketDisconnect:
        logger.info("Agent [%s] closed the WebSocket connection.", agent_id)
    except Exception as exc:
        logger.error("Unexpected socket error on Agent [%s]: %s", agent_id, exc)
    finally:
        # Mandatory cleanup to prevent dangling sockets and clear Redis state
        await ws_manager.disconnect(agent_id)