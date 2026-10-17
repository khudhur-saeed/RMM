import logging
from typing import Dict, Union
from uuid import UUID

from fastapi import WebSocket
import redis.asyncio as redis

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
            host="127.0.0.1",
            port=6379,
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

    async def disconnect(self, agent_id: Union[UUID, str]) -> None:
        """Purges agent socket from memory and marks offline in Redis."""
        key = self._canonical_id(agent_id)
        if key in self.active_connections:
            del self.active_connections[key]

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

    def disconnect_operator(self, agent_id: Union[UUID, str]) -> None:
        """Removes operator socket from memory."""
        key = self._canonical_id(agent_id)
        if key in self.operator_connections:
            del self.operator_connections[key]
            logger.info("Operator tunnel disconnected for Agent [%s].", key)

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
            logger.error("Failed to route data to operator [%s]: %v", key, exc)
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
            logger.error("Failed to route frame to agent [%s]: %v", key, exc)
            return False


# Global Singleton Instance
ws_manager = ConnectionManager()
