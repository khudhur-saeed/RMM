import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.core.ws_manager import ws_manager
from app.models.agent import Agent

logger = logging.getLogger("rmm.websocket")

router = APIRouter()


@router.websocket("/agent/{agent_id}")
async def agent_websocket_endpoint(
    websocket: WebSocket,
    agent_id: UUID,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    # 1. المصادقة الصارمة للعميل أثناء المصافحة
    query = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = query.scalar_one_or_none()

    if not agent or not agent.api_key_hash:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(token_hash, agent.api_key_hash):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 2. تسجيل الاتصال في مدير المقابس ومزامنة الحالة مع Redis
    await ws_manager.connect(agent_id, websocket)

    # 3. تحديث last_seen فور نجاح الاتصال
    await db.execute(
        update(Agent)
        .where(Agent.id == agent_id)
        .values(last_seen=datetime.now(timezone.utc))
    )
    await db.commit()
    logger.info("Agent [%s] connected and last_seen updated in PostgreSQL.", agent_id)

    try:
        while True:
            data = await websocket.receive_text()

            # تجديد الـ TTL في Redis وتحديث last_seen في PostgreSQL مع كل إطار
            await ws_manager.redis_client.set(name=f"agent:{agent_id}:status", value="online", ex=60)
            await db.execute(
                update(Agent)
                .where(Agent.id == agent_id)
                .values(last_seen=datetime.now(timezone.utc))
            )
            await db.commit()

            try:
                payload = json.loads(data)
                msg_type = payload.get("type")

                # تمرير مخرجات الطرفية للمشغل إن وجدت
                if msg_type == "term_out":
                    term_data = payload.get("payload", "")
                    await ws_manager.route_to_operator(agent_id, term_data)

            except json.JSONDecodeError:
                pass

    except WebSocketDisconnect:
        logger.info("Agent [%s] disconnected.", agent_id)
    finally:
        await ws_manager.disconnect(agent_id)


@router.websocket("/operator/{agent_id}")
async def operator_websocket_endpoint(
    websocket: WebSocket,
    agent_id: UUID,
):
    if not await ws_manager.connect_operator(agent_id, websocket):
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
        return

    try:
        while True:
            raw_keystroke = await websocket.receive_text()
            frame = json.dumps({
                "type": "term_in",
                "payload": raw_keystroke,
            })
            await ws_manager.route_to_agent(agent_id, frame)
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect_operator(agent_id)
