import logging
from typing import Dict
from uuid import UUID

from fastapi import WebSocket
import redis.asyncio as redis

logger = logging.getLogger("rmm.websocket")


class ConnectionManager:
    """
    Manages active WebSocket connections locally and syncs
    ephemeral agent status to a global Redis datastore.
    """

    def __init__(self) -> None:
        self.active_connections: Dict[UUID, WebSocket] = {}
        self.redis_client = redis.Redis(
            host="127.0.0.1",
            port=6379,
            decode_responses=True,
        )

    async def connect(self, agent_id: UUID, websocket: WebSocket) -> None:
        """
        Accepts the socket, stores it locally, and publishes the online
        status to Redis with a 60-second TTL (Time-To-Live).
        """
        await websocket.accept()
        self.active_connections[agent_id] = websocket

        redis_key = f"agent:{agent_id}:status"
        await self.redis_client.set(name=redis_key, value="online", ex=60)

        logger.info(
            "Agent [%s] WebSocket established & synced to Redis. Active local nodes: %d",
            agent_id,
            len(self.active_connections),
        )

    async def disconnect(self, agent_id: UUID) -> None:
        """
        Removes the socket from local memory and immediately purges
        the online status key from Redis.
        """
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]

        redis_key = f"agent:{agent_id}:status"
        await self.redis_client.delete(redis_key)

        logger.info(
            "Agent [%s] WebSocket disconnected & removed from Redis. Active local nodes: %d",
            agent_id,
            len(self.active_connections),
        )

    async def send_json(self, agent_id: UUID, payload: dict) -> bool:
        """
        Dispatches JSON to a locally connected agent.
        """
        websocket = self.active_connections.get(agent_id)
        if not websocket:
            logger.warning("Local dispatch failed: Agent [%s] socket not in memory.", agent_id)
            return False

        try:
            await websocket.send_json(payload)
            return True
        except Exception as exc:
            logger.error("Error dispatching JSON to agent [%s]: %s", agent_id, exc)
            await self.disconnect(agent_id)
            return False


# Global Singleton Instance
ws_manager = ConnectionManager()