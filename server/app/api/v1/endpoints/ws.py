from datetime import datetime, timezone
import hashlib
import json
import logging
import secrets
import time
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from pydantic import ValidationError
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import compute_output_hash, record_audit_log
from app.core.crypto import compute_task_digest, sign_task_dispatch
from app.core.rbac import (
    authenticate_ws_operator,
    extract_bearer_token,
    verify_ws_agent_access,
    verify_ws_dispatch_permission,
)
from app.core.ws_manager import ws_manager
from app.db.session import async_session_factory
from app.models.agent import Agent
from app.models.software import InstalledSoftware
from app.schemas.task import TaskDispatchFrame, TaskExitFrame, TaskStreamFrame
from app.schemas.telemetry import (
    AuthEventPayload,
    HardwareMetricsPayload,
    ServiceStatusPayload,
)
from app.services.alert_engine import alert_evaluator

logger = logging.getLogger("rmm.websocket")

router = APIRouter()

# Minimum interval (in seconds) between PostgreSQL last_seen writes per connected agent
DB_LAST_SEEN_SYNC_INTERVAL_SEC = 30.0


async def _update_agent_last_seen(agent_id: UUID) -> None:
    """Updates the agent's last_seen timestamp using a short-lived DB session."""
    async with async_session_factory() as db:
        await db.execute(
            update(Agent)
            .where(Agent.id == agent_id)
            .values(last_seen=datetime.now(timezone.utc))
        )
        await db.commit()


async def _persist_software_inventory(
    agent_id: UUID,
    software_list: list[dict[str, Any]],
    session: AsyncSession,
) -> int:
    """Atomically replaces the agent's installed software catalog inside PostgreSQL."""
    seen: set[tuple[str, str]] = set()
    records: list[InstalledSoftware] = []

    for pkg in software_list:
        if not isinstance(pkg, dict):
            continue
        raw_name = str(pkg.get("name") or "").strip()
        if not raw_name:
            continue

        name = raw_name[:255]
        version_raw = str(pkg.get("version") or "").strip()
        version = version_raw[:128] if version_raw else None

        publisher_raw = str(pkg.get("publisher") or "").strip()
        publisher = publisher_raw[:255] if publisher_raw else None

        install_date_raw = str(pkg.get("install_date") or "").strip()
        install_date = install_date_raw[:64] if install_date_raw else None

        dedup_key = (name.lower(), (version or "").lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        records.append(
            InstalledSoftware(
                agent_id=agent_id,
                name=name,
                version=version,
                publisher=publisher,
                install_date=install_date,
            )
        )

    await session.execute(
        delete(InstalledSoftware).where(InstalledSoftware.agent_id == agent_id)
    )
    if records:
        session.add_all(records)
    await session.commit()
    return len(records)


async def handle_software_inventory(
    agent_id: UUID, payload: Dict[str, Any], db: Optional[AsyncSession] = None
) -> int:
    """
    Processes incoming installed software inventory frames from the agent
    and synchronizes the full package catalog into PostgreSQL.
    """
    try:
        software_list = payload.get("software", [])
        if not isinstance(software_list, list):
            logger.warning(
                "[-] [SoftwareInventory] Malformed payload received for Agent [%s]",
                agent_id,
            )
            return 0

        if db is not None:
            stored_count = await _persist_software_inventory(agent_id, software_list, db)
        else:
            async with async_session_factory() as session:
                stored_count = await _persist_software_inventory(
                    agent_id, software_list, session
                )

        logger.info(
            "[+] [SoftwareInventory] Synchronized %d installed packages for Agent [%s]",
            stored_count,
            agent_id,
        )
        return stored_count

    except Exception as exc:
        logger.warning(
            "Unexpected error evaluating software inventory from agent %s: %s",
            agent_id,
            exc,
        )
        return 0


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
    token: Optional[str] = Query(default=None),
):
    # 1. Extract token from Authorization header (preferred) or query parameter fallback
    raw_token = (
        extract_bearer_token(
            websocket.headers.get("authorization"),
            websocket.headers.get("x-api-key"),
        )
        or token
    )

    if not raw_token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 2. Authenticate agent using a short-lived DB session (avoids pinning pool connections)
    async with async_session_factory() as db:
        query = await db.execute(select(Agent).where(Agent.id == agent_id))
        agent = query.scalar_one_or_none()
        api_key_hash = agent.api_key_hash if agent else None

    if not api_key_hash:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(token_hash, api_key_hash):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 3. Register connection in ConnectionManager and sync online status in Redis
    await ws_manager.connect(agent_id, websocket)

    # 4. Update last_seen immediately upon connection
    await _update_agent_last_seen(agent_id)
    last_db_sync = time.monotonic()
    logger.info("Agent [%s] connected and last_seen updated in PostgreSQL.", agent_id)

    canonical_key = str(agent_id).lower()

    try:
        while True:
            data = await websocket.receive_text()

            # Refresh Redis online TTL on every frame
            await ws_manager.redis_client.set(
                name=f"agent:{canonical_key}:status",
                value="online",
                ex=60,
            )

            msg_type: Optional[str] = None
            payload: Optional[dict] = None
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    payload = parsed
                    msg_type = parsed.get("type")
            except json.JSONDecodeError:
                pass

            # Throttle PostgreSQL last_seen writes to at most once per DB_LAST_SEEN_SYNC_INTERVAL_SEC
            now_mono = time.monotonic()
            if (now_mono - last_db_sync) >= DB_LAST_SEEN_SYNC_INTERVAL_SEC:
                await _update_agent_last_seen(agent_id)
                last_db_sync = now_mono

            if not payload or not msg_type:
                continue

            if msg_type == "term_out":
                term_data = payload.get("payload", "")
                if isinstance(term_data, str):
                    await ws_manager.route_to_operator(agent_id, term_data)

            elif msg_type == "task_stream":
                try:
                    stream_frame = TaskStreamFrame.model_validate(payload)
                    ws_manager.append_task_output(stream_frame.task_id, stream_frame.chunk)
                    await ws_manager.route_to_operator(agent_id, stream_frame.chunk)
                except ValidationError as exc:
                    logger.warning(
                        "Invalid task_stream frame from Agent [%s]: %s", agent_id, exc
                    )

            elif msg_type == "task_exit":
                try:
                    exit_frame = TaskExitFrame.model_validate(payload)
                    summary = (
                        f"\r\n[Task {exit_frame.task_id}] Exited with code {exit_frame.exit_code} "
                        f"({exit_frame.elapsed_ms}ms)\r\n"
                    )
                    await ws_manager.route_to_operator(agent_id, summary)

                    task_ctx = ws_manager.finalize_task_output(exit_frame.task_id)
                    active_op = ws_manager.operator_principals.get(canonical_key)
                    task_principal = (
                        task_ctx.get("principal") if task_ctx else None
                    ) or active_op
                    cmd_text = (
                        task_ctx.get("command_text")
                        if task_ctx and task_ctx.get("command_text")
                        else f"task:{exit_frame.task_id}"
                    )
                    raw_output = (
                        task_ctx.get("full_output")
                        if task_ctx and task_ctx.get("full_output")
                        else summary
                    )
                    await record_audit_log(
                        principal=task_principal,
                        target_agent_id=agent_id,
                        task_id=exit_frame.task_id,
                        action="WS_TASK_COMPLETE",
                        method="WS",
                        path=f"/api/v1/ws/agent/{agent_id}",
                        command_text=cmd_text,
                        output_hash=compute_output_hash(raw_output),
                        status_code=200 if exit_frame.exit_code == 0 else 500,
                        details={
                            "exit_code": exit_frame.exit_code,
                            "elapsed_ms": exit_frame.elapsed_ms,
                            "error": exit_frame.error,
                        },
                    )
                except ValidationError as exc:
                    logger.warning(
                        "Invalid task_exit frame from Agent [%s]: %s", agent_id, exc
                    )

            elif msg_type == "software_inventory":
                await handle_software_inventory(agent_id, payload)
                await ws_manager.cache_telemetry(agent_id, msg_type, payload)

            else:
                if msg_type in ("heartbeat", "hardware_telemetry", "network_telemetry"):
                    await ws_manager.cache_telemetry(agent_id, msg_type, payload)
                await process_telemetry_frame(agent_id, payload)

    except WebSocketDisconnect:
        logger.info("Agent [%s] disconnected.", agent_id)
    finally:
        await ws_manager.disconnect(agent_id, websocket=websocket)


@router.websocket("/operator/{agent_id}")
async def operator_websocket_endpoint(
    websocket: WebSocket,
    agent_id: UUID,
    token: Optional[str] = Query(default=None),
):
    # 1. Authenticate operator token and resolve RBAC Principal (`ws:connect`)
    principal = await authenticate_ws_operator(websocket, query_token=token)
    if principal is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 2. Enforce site/organization boundary before accepting the WebSocket
    if not await verify_ws_agent_access(principal, agent_id):
        logger.warning(
            "Operator [%s] (role=%s) denied WebSocket access to Agent [%s] outside site scope.",
            principal.username,
            principal.role.value,
            agent_id,
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # 3. Bind operator socket if target agent is online
    if not await ws_manager.connect_operator(agent_id, websocket, principal=principal):
        await websocket.close(code=status.WS_1013_TRY_AGAIN_LATER)
        return

    try:
        while True:
            raw_message = await websocket.receive_text()

            # 4. Enforce RBAC permission check on all WebSocket dispatch actions
            # (Auditor may passively observe agent output, but is forbidden from dispatching input/tasks)
            if not verify_ws_dispatch_permission(principal):
                logger.warning(
                    "Operator [%s] (role=%s) blocked from WebSocket dispatch action on Agent [%s].",
                    principal.username,
                    principal.role.value,
                    agent_id,
                )
                err_payload = json.dumps(
                    {
                        "type": "error",
                        "code": status.HTTP_403_FORBIDDEN,
                        "detail": (
                            f"Permission denied: role '{principal.role.value}' is not "
                            "authorized to dispatch commands or terminal input over WebSocket."
                        ),
                    }
                )
                await record_audit_log(
                    principal=principal,
                    target_agent_id=agent_id,
                    action="WS_DISPATCH_DENIED",
                    method="WS",
                    path=f"/api/v1/ws/operator/{agent_id}",
                    command_text=raw_message,
                    output_hash=compute_output_hash(err_payload),
                    status_code=status.HTTP_403_FORBIDDEN,
                )
                await websocket.send_text(err_payload)
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return

            # 5. Parse structured dispatch frames (`task_dispatch` / `term_in`) or fallback to raw keystroke `term_in`
            outbound_frame: Optional[str] = None
            audit_action = "WS_TERM_IN"
            audit_command_text = raw_message
            audit_task_id: Optional[UUID] = None
            try:
                parsed = json.loads(raw_message)
                if isinstance(parsed, dict) and "type" in parsed:
                    action_type = parsed.get("type")
                    if action_type == "task_dispatch":
                        cmd = str(parsed.get("command") or "").strip()
                        if not cmd:
                            continue
                        timeout_sec = int(parsed.get("timeout_sec") or 30)
                        raw_tid = parsed.get("task_id")
                        task_id = UUID(str(raw_tid)) if raw_tid else uuid4()
                        digest = parsed.get("payload_sha256") or compute_task_digest(
                            task_id=task_id,
                            command=cmd,
                            timeout_sec=timeout_sec,
                        )
                        sig = parsed.get("signature") or sign_task_dispatch(
                            task_id=task_id,
                            command=cmd,
                            timeout_sec=timeout_sec,
                        )
                        task_frame = TaskDispatchFrame(
                            task_id=task_id,
                            command=cmd,
                            timeout_sec=timeout_sec,
                            payload_sha256=digest,
                            signature=sig,
                        )
                        outbound_frame = task_frame.model_dump_json()
                        audit_action = "WS_TASK_DISPATCH"
                        audit_command_text = cmd
                        audit_task_id = task_id
                        ws_manager.register_dispatched_task(
                            task_id=task_id,
                            agent_id=agent_id,
                            command_text=cmd,
                            principal=principal,
                        )
                    elif action_type == "term_in":
                        term_payload = str(parsed.get("payload") or "")
                        outbound_frame = json.dumps(
                            {
                                "type": "term_in",
                                "payload": term_payload,
                            }
                        )
                        audit_action = "WS_TERM_IN"
                        audit_command_text = term_payload
            except (json.JSONDecodeError, ValueError, TypeError):
                outbound_frame = None

            if outbound_frame is None:
                outbound_frame = json.dumps(
                    {
                        "type": "term_in",
                        "payload": raw_message,
                    }
                )

            await ws_manager.route_to_agent(
                agent_id,
                outbound_frame,
                principal=principal,
            )
            await record_audit_log(
                principal=principal,
                target_agent_id=agent_id,
                task_id=audit_task_id,
                action=audit_action,
                method="WS",
                path=f"/api/v1/ws/operator/{agent_id}",
                command_text=audit_command_text,
                output_hash=compute_output_hash(outbound_frame),
                status_code=200,
            )
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect_operator(agent_id, websocket=websocket)
