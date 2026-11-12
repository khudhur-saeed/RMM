import asyncio
import json
import logging
import time
from typing import Any, Dict, Optional, Union
from uuid import UUID

from fastapi import HTTPException, WebSocket, status
import redis.asyncio as redis

from app.core.config import settings

logger = logging.getLogger("rmm.websocket")


class ConnectionManager:
    """
    Manages active WebSocket connections for endpoint agents and operators,
    ensuring thread-safe real-time bidirectional terminal routing and RBAC enforcement.
    """

    def __init__(self) -> None:
        # Agent socket registry: canonical string agent_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}

        # Operator socket registry: canonical string agent_id -> WebSocket
        self.operator_connections: Dict[str, WebSocket] = {}

        # Operator RBAC principal registry: canonical string agent_id -> Principal
        self.operator_principals: Dict[str, Any] = {}

        # Active C2 task context registry for correlating command_text with streamed output hashes
        self.dispatched_tasks: Dict[str, Dict[str, Any]] = {}

        # Async Redis client for state synchronization
        self.redis_client = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            decode_responses=True,
        )

    def _canonical_id(self, agent_id: Union[UUID, str]) -> str:
        """Converts UUID or string to uniform lowercase string key."""
        return str(agent_id).lower()

    def _negotiate_subprotocol(self, websocket: WebSocket) -> Optional[str]:
        if not isinstance(websocket, WebSocket):
            return None
        headers = getattr(websocket, "headers", None)
        proto_header = headers.get("sec-websocket-protocol") if headers is not None else None
        if isinstance(proto_header, str) and proto_header:
            for item in proto_header.split(","):
                if item.strip() == "rmm.v1":
                    return "rmm.v1"
        return None

    async def connect(self, agent_id: Union[UUID, str], websocket: WebSocket) -> None:
        """Registers active agent socket and synchronizes online state to Redis."""
        key = self._canonical_id(agent_id)
        subproto = self._negotiate_subprotocol(websocket)
        if subproto:
            await websocket.accept(subprotocol=subproto)
        else:
            await websocket.accept()
        self.active_connections[key] = websocket

        redis_key = f"agent:{key}:status"
        await self.redis_client.set(name=redis_key, value="online", ex=60)

        logger.info(
            "Agent [%s] WebSocket established. Active agents: %d",
            key,
            len(self.active_connections),
        )

    async def disconnect(
        self,
        agent_id: Union[UUID, str],
        websocket: Optional[WebSocket] = None,
    ) -> None:
        """
        Purges agent socket from memory and marks offline in Redis.
        When `websocket` is supplied, guards against evicting a newer reconnected socket.
        When `websocket` is None (e.g. Watchdog eviction), closes the stale socket handle.
        """
        key = self._canonical_id(agent_id)
        current_ws = self.active_connections.get(key)

        if (
            websocket is not None
            and current_ws is not None
            and current_ws is not websocket
        ):
            logger.debug(
                "Skipping stale disconnect cleanup for superseded Agent [%s] socket.",
                key,
            )
            return

        removed_ws = self.active_connections.pop(key, None)
        if websocket is None and removed_ws is not None:
            try:
                await removed_ws.close()
            except Exception:
                pass

        redis_key = f"agent:{key}:status"
        await self.redis_client.delete(redis_key)

        # Evict pending task buffers for disconnected agent to prevent memory leaks
        orphaned = [
            t_id for t_id, ctx in self.dispatched_tasks.items()
            if ctx.get("agent_id") == key
        ]
        for t_id in orphaned:
            self.dispatched_tasks.pop(t_id, None)

        logger.info(
            "Agent [%s] WebSocket disconnected. Active agents: %d",
            key,
            len(self.active_connections),
        )

    async def connect_operator(
        self,
        agent_id: Union[UUID, str],
        websocket: WebSocket,
        principal: Optional[Any] = None,
    ) -> bool:
        """Accepts operator socket if target agent is actively registered locally or across Redis cluster."""
        key = self._canonical_id(agent_id)
        is_online = key in self.active_connections
        if not is_online:
            try:
                redis_state = await self.redis_client.get(f"agent:{key}:status")
                is_online = redis_state == "online"
            except Exception:
                is_online = False

        if not is_online:
            logger.warning(
                "Operator denied: Target Agent [%s] is currently offline.", key
            )
            return False

        subproto = self._negotiate_subprotocol(websocket)
        if subproto:
            await websocket.accept(subprotocol=subproto)
        else:
            await websocket.accept()
        self.operator_connections[key] = websocket
        if principal is not None:
            self.operator_principals[key] = principal
        logger.info(
            "Operator tunnel established for Agent [%s]. Active operators: %d",
            key,
            len(self.operator_connections),
        )
        return True

    def disconnect_operator(
        self,
        agent_id: Union[UUID, str],
        websocket: Optional[WebSocket] = None,
    ) -> None:
        """Removes operator socket from memory if it matches the active instance."""
        key = self._canonical_id(agent_id)
        current_ws = self.operator_connections.get(key)
        if (
            websocket is not None
            and current_ws is not None
            and current_ws is not websocket
        ):
            return

        self.operator_principals.pop(key, None)
        if key in self.operator_connections:
            del self.operator_connections[key]
            logger.info("Operator tunnel disconnected for Agent [%s].", key)

    async def cache_telemetry(
        self,
        agent_id: Union[UUID, str],
        category: str,
        payload: Dict[str, Any],
    ) -> None:
        """Caches the latest agent telemetry frame in Redis with a 5-minute TTL."""
        key = self._canonical_id(agent_id)
        redis_key = f"agent:{key}:telemetry:{category}"
        await self.redis_client.set(name=redis_key, value=json.dumps(payload), ex=300)

    async def get_telemetry(self, agent_id: Union[UUID, str]) -> Dict[str, Any]:
        """Retrieves cached heartbeat, hardware, and network telemetry snapshots from Redis."""
        key = self._canonical_id(agent_id)
        categories = ("heartbeat", "hardware_telemetry", "network_telemetry")
        keys = [f"agent:{key}:telemetry:{cat}" for cat in categories]
        raw_values = await self.redis_client.mget(keys)

        result: Dict[str, Any] = {}
        for cat, raw in zip(categories, raw_values):
            if raw:
                try:
                    result[cat] = json.loads(raw)
                except json.JSONDecodeError:
                    result[cat] = None
            else:
                result[cat] = None
        return result

    async def route_to_operator(self, agent_id: Union[UUID, str], data: str) -> bool:
        """Routes raw stdout/echo from Agent PTY to Operator's xterm.js locally or via Redis Pub/Sub."""
        key = self._canonical_id(agent_id)
        operator_ws = self.operator_connections.get(key)
        if operator_ws:
            try:
                await operator_ws.send_text(data)
                return True
            except Exception as exc:
                logger.error("Failed to route data to operator [%s]: %s", key, exc)
                self.disconnect_operator(key)
                return False

        try:
            subscribers = await self.redis_client.publish(f"c2:operator:{key}:inbox", data)
            return bool(subscribers and int(subscribers) > 0)
        except Exception:
            return False

    async def route_to_agent(
        self,
        agent_id: Union[UUID, str],
        frame_json: str,
        principal: Optional[Any] = None,
    ) -> bool:
        """
        Routes C2 task frames or terminal keystrokes from Operator to Agent PTY
        locally or across horizontal workers via Redis Pub/Sub.
        When `principal` is provided, enforces `agents:dispatch` and `ws:dispatch` permissions.
        """
        if principal is not None:
            if not (
                principal.has_permission("agents:dispatch")
                and principal.has_permission("ws:dispatch")
            ):
                role_label = getattr(principal.role, "value", str(principal.role))
                logger.warning(
                    "Blocked unauthorized C2 dispatch to Agent [%s] by role [%s].",
                    agent_id,
                    role_label,
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"Permission denied: role '{role_label}' is not authorized "
                        "to dispatch frames to agents."
                    ),
                )

        key = self._canonical_id(agent_id)
        agent_ws = self.active_connections.get(key)
        if agent_ws:
            try:
                await agent_ws.send_text(frame_json)
                return True
            except Exception as exc:
                logger.error("Failed to route frame to agent [%s]: %s", key, exc)
                return False

        try:
            redis_state = await self.redis_client.get(f"agent:{key}:status")
            if redis_state == "online":
                await self.redis_client.publish(f"c2:agent:{key}:inbox", frame_json)
                return True
        except Exception as exc:
            logger.debug("Redis Pub/Sub fallback failed for agent [%s]: %s", key, exc)
        return False

    def register_dispatched_task(
        self,
        task_id: Union[UUID, str],
        agent_id: Union[UUID, str],
        command_text: str,
        principal: Optional[Any] = None,
    ) -> None:
        """Tracks a dispatched C2 task so streamed agent output can be hashed into audit_logs."""
        now = time.monotonic()
        # Evict stale tasks older than 30 minutes to prevent unbounded memory growth
        stale = [
            t_id for t_id, ctx in self.dispatched_tasks.items()
            if (now - ctx.get("created_at", now)) > 1800
        ]
        for t_id in stale:
            self.dispatched_tasks.pop(t_id, None)

        t_key = self._canonical_id(task_id)
        self.dispatched_tasks[t_key] = {
            "task_id": str(task_id),
            "agent_id": self._canonical_id(agent_id),
            "command_text": command_text,
            "principal": principal,
            "chunks": [],
            "total_bytes": 0,
            "created_at": now,
        }

    def append_task_output(self, task_id: Union[UUID, str], chunk: str) -> None:
        """Appends a stdout/stderr stream chunk to an in-flight task's buffer (capped at 10MB)."""
        t_key = self._canonical_id(task_id)
        ctx = self.dispatched_tasks.get(t_key)
        if ctx is not None:
            current_bytes = ctx.get("total_bytes", 0)
            if current_bytes < 10 * 1024 * 1024:
                ctx["chunks"].append(chunk)
                ctx["total_bytes"] = current_bytes + len(chunk.encode("utf-8"))

    def finalize_task_output(
        self, task_id: Union[UUID, str]
    ) -> Optional[Dict[str, Any]]:
        """Pops and returns the completed task context and concatenated output string."""
        t_key = self._canonical_id(task_id)
        ctx = self.dispatched_tasks.pop(t_key, None)
        if ctx is None:
            return None
        ctx["full_output"] = "".join(ctx.get("chunks", []))
        return ctx

    async def run_pubsub_listener(self) -> None:
        """
        Subscribes to `c2:agent:*:inbox` and `c2:operator:*:inbox` in Redis so
        frames published by horizontal workers are delivered to locally held sockets.
        """
        pubsub_redis = redis.Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            decode_responses=True,
        )
        pubsub = pubsub_redis.pubsub()
        try:
            await pubsub.psubscribe("c2:agent:*:inbox", "c2:operator:*:inbox")
            while True:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "pmessage":
                    channel = str(msg.get("channel", ""))
                    data = str(msg.get("data", ""))
                    parts = channel.split(":")
                    if len(parts) == 4 and parts[0] == "c2" and parts[3] == "inbox":
                        target_kind, key = parts[1], parts[2].lower()
                        if target_kind == "agent":
                            agent_ws = self.active_connections.get(key)
                            if agent_ws is not None:
                                try:
                                    await agent_ws.send_text(data)
                                except Exception:
                                    pass
                        elif target_kind == "operator":
                            op_ws = self.operator_connections.get(key)
                            if op_ws is not None:
                                try:
                                    await op_ws.send_text(data)
                                except Exception:
                                    self.disconnect_operator(key)
                else:
                    await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug("Redis Pub/Sub listener stopped: %s", exc)
        finally:
            try:
                await pubsub.aclose()
                await pubsub_redis.aclose()
            except Exception:
                pass


# Global Singleton Instance
ws_manager = ConnectionManager()
