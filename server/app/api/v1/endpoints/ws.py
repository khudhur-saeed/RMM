import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import UUID

from app.core.ws_manager import ws_manager
from app.db.session import get_db
from app.models.agent import Agent
from app.schemas.telemetry import (
    AuthEventPayload,
    HardwareMetricsPayload,
    ServiceStatusPayload,
)
from app.services.alert_engine import alert_evaluator
from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("rmm.websocket")

router = APIRouter()


async def handle_software_inventory(
    agent_id: UUID, payload: Dict[str, Any], db: AsyncSession
) -> None:
    """
    Processes incoming installed software inventory frames from the agent.
    """
    try:
        software_list = payload.get("software", [])
        if not isinstance(software_list, list):
            logger.warning(
                "[-] [SoftwareInventory] Malformed payload received for Agent [%s]",
                agent_id,
            )
            return

        logger.info(
            "[+] [SoftwareInventory] Received %d installed packages from Agent [%s]",
            len(software_list),
            agent_id,
        )

        # Forensic sample inspection for the first few packages
        for pkg in software_list[:5]:
            name = pkg.get("name", "Unknown")
            version = pkg.get("version", "N/A")
            publisher = pkg.get("publisher", "Unknown")
            logger.debug(
                "    * Package: %s (Version: %s, Publisher: %s)",
                name,
                version,
                publisher,
            )

    except Exception as exc:
        logger.warning(
            "Unexpected error evaluating software inventory from agent %s: %s",
            agent_id,
            exc,
        )


async def process_telemetry_frame(agent_id: UUID, payload: dict) -> None:
    """
    Evaluates inbound telemetry frames against the alert engine without interrupting the socket.
    """
    try:
        frame_type = payload.get("type")

        if frame_type == "hardware_telemetry":
            cpu_val = payload.get("cpu", {}).get(
                "usage_percent", payload.get("cpu_percent", 0.0)
            )
            mem_val = payload.get("memory", {}).get(
                "used_percent", payload.get("memory_percent", 0.0)
            )
            hw_payload = HardwareMetricsPayload(
                cpu_percent=cpu_val, memory_percent=mem_val
            )
            alerts = alert_evaluator.evaluate_hardware(agent_id, hw_payload)
            for alert in alerts:
                logger.warning(
                    f"[ALERT GENERATED] [{alert.severity.value}] Agent {alert.agent_id} | "
                    f"Category: {alert.category.value} | Title: {alert.title} | {alert.message}"
                )

        elif frame_type == "service_status":
            svc_payload = ServiceStatusPayload(**payload.get("payload", payload))
            alerts = alert_evaluator.evaluate_services(agent_id, svc_payload)
            for alert in alerts:
                logger.error(
                    f"[ALERT GENERATED] [{alert.severity.value}] Agent {alert.agent_id} | "
                    f"Category: {alert.category.value} | Title: {alert.title} | {alert.message}"
                )

        elif frame_type in ("auth_event", "security_event_telemetry"):
            events = payload.get("events", [payload.get("payload", payload)])
            for ev in events:
                event_type = ev.get("event_type") or (
                    "LOGON_FAILED_4625" if ev.get("event_id") == 4625 else "OTHER"
                )
                user = ev.get("user") or ev.get("target_user_name") or "unknown"
                src_ip = ev.get("source_ip") or ev.get("ip_address")

                auth_payload = AuthEventPayload(
                    event_type=event_type,
                    username=user,
                    source_ip=src_ip,
                )
                alerts = alert_evaluator.evaluate_auth_event(agent_id, auth_payload)
                for alert in alerts:
                    logger.error(
                        f"[ALERT GENERATED] [{alert.severity.value}] Agent {alert.agent_id} | "
                        f"Category: {alert.category.value} | Title: {alert.title} | {alert.message}"
                    )

    except ValidationError as err:
        logger.debug(f"Telemetry frame schema mismatch from agent {agent_id}: {err}")
    except Exception as exc:
        logger.warning(
            f"Unexpected error evaluating telemetry frame from agent {agent_id}: {exc}"
        )


@router.websocket("/agent/{agent_id}")
async def agent_websocket_endpoint(
    websocket: WebSocket,
    agent_id: UUID,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db),
):
    query = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = query.scalar_one_or_none()

    if not agent or not agent.api_key_hash:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(token_hash, agent.api_key_hash):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(agent_id, websocket)

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

            await ws_manager.redis_client.set(
                name=f"agent:{agent_id}:status", value="online", ex=60
            )
            await db.execute(
                update(Agent)
                .where(Agent.id == agent_id)
                .values(last_seen=datetime.now(timezone.utc))
            )
            await db.commit()

            try:
                payload = json.loads(data)
                msg_type = payload.get("type")

                if msg_type == "term_out":
                    term_data = payload.get("payload", "")
                    await ws_manager.route_to_operator(agent_id, term_data)

                elif msg_type == "software_inventory":
                    await handle_software_inventory(agent_id, payload, db)

                else:
                    await process_telemetry_frame(agent_id, payload)

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
            frame = json.dumps(
                {
                    "type": "term_in",
                    "payload": raw_keystroke,
                }
            )
            await ws_manager.route_to_agent(agent_id, frame)
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect_operator(agent_id)
