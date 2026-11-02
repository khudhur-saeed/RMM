import json
import logging
from typing import Any, Dict, Optional, Union
from uuid import UUID

from fastapi import WebSocket
import redis.asyncio as redis

from app.core.config import settings

logger = logging.getLogger("rmm.websocket")


class ConnectionManager:
    """
    Manages active WebSocket connections for endpoint agents and operators,
    ensuring thread-safe real-time bidirectional terminal routing.
    """

    def __init__(self) -> None:
        # Agent socket registry: canonical string agent_id -> WebSocket
        self.active_connections: Dict[str, WebSocket] = {}

        # Operator socket registry: canonical string agent_id -> WebSocket
        self.operator_connections: Dict[str, WebSocket] = {}

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

    async def connect(self, agent_id: Union[UUID, str], websocket: WebSocket) -> None:
        """Registers active agent socket and synchronizes online state to Redis."""
        key = self._canonical_id(agent_id)
        await websocket.accept()
        self.active_connections[key] = websocket

        redis_key = f"agent:{key}:status"
        await self.redis_client.set(name=redis_key, value="online", ex=60)

        logger.info("Agent [%s] WebSocket established. Active agents: %d", key, len(self.active_connections))

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

        if websocket is not None and current_ws is not None and current_ws is not websocket:
            logger.debug("Skipping stale disconnect cleanup for superseded Agent [%s] socket.", key)
            return

        removed_ws = self.active_connections.pop(key, None)
        if websocket is None and removed_ws is not None:
            try:
                await removed_ws.close()
            except Exception:
                pass

        redis_key = f"agent:{key}:status"
        await self.redis_client.delete(redis_key)

        logger.info("Agent [%s] WebSocket disconnected. Active agents: %d", key, len(self.active_connections))

    async def connect_operator(self, agent_id: Union[UUID, str], websocket: WebSocket) -> bool:
        """Accepts operator socket only if target agent is actively registered."""
        key = self._canonical_id(agent_id)
        if key not in self.active_connections:
            logger.warning("Operator denied: Target Agent [%s] is currently offline.", key)
            return False

        await websocket.accept()
        self.operator_connections[key] = websocket
        logger.info("Operator tunnel established for Agent [%s]. Active operators: %d", key, len(self.operator_connections))
        return True

    def disconnect_operator(
        self,
        agent_id: Union[UUID, str],
        websocket: Optional[WebSocket] = None,
    ) -> None:
        """Removes operator socket from memory if it matches the active instance."""
        key = self._canonical_id(agent_id)
        current_ws = self.operator_connections.get(key)
        if websocket is not None and current_ws is not None and current_ws is not websocket:
            return

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
        """Routes raw stdout/echo from Agent PTY to Operator's xterm.js."""
        key = self._canonical_id(agent_id)
        operator_ws = self.operator_connections.get(key)
        if not operator_ws:
            return False

        try:
            await operator_ws.send_text(data)
            return True
        except Exception as exc:
            logger.error("Failed to route data to operator [%s]: %s", key, exc)
            self.disconnect_operator(key)
            return False

    async def route_to_agent(self, agent_id: Union[UUID, str], frame_json: str) -> bool:
        """Routes raw keystrokes from Operator to Agent PTY."""
        key = self._canonical_id(agent_id)
        agent_ws = self.active_connections.get(key)
        if not agent_ws:
            return False

        try:
            await agent_ws.send_text(frame_json)
            return True
        except Exception as exc:
            logger.error("Failed to route frame to agent [%s]: %s", key, exc)
            return False


# Global Singleton Instance
ws_manager = ConnectionManager()
