import logging
from typing import Dict
from uuid import UUID

from fastapi import WebSocket

logger = logging.getLogger("rmm.websocket")


class ConnectionManager:
    """
    Manages active, authenticated full-duplex WebSocket connections
    for monitored endpoint agents.
    """

    def __init__(self) -> None:
        self.active_connections: Dict[UUID, WebSocket] = {}

    async def connect(self, agent_id: UUID, websocket: WebSocket) -> None:
        """
        Accepts the pending WebSocket handshake upgrade and registers
        the active socket mapped to the agent's unique identifier.
        """
        await websocket.accept()
        self.active_connections[agent_id] = websocket
        logger.info(
            "Agent [%s] WebSocket tunnel established. Active nodes: %d",
            agent_id,
            len(self.active_connections),
        )

    def disconnect(self, agent_id: UUID) -> None:
        """
        Unregisters an agent's socket from active memory tracking upon
        connection drop or explicit socket termination.
        """
        if agent_id in self.active_connections:
            del self.active_connections[agent_id]
            logger.info(
                "Agent [%s] WebSocket disconnected. Active nodes: %d",
                agent_id,
                len(self.active_connections),
            )

    async def send_json(self, agent_id: UUID, payload: dict) -> bool:
        """
        Dispatches a structured JSON payload directly to the target agent.
        Returns True if delivered, False if the target is offline.
        """
        websocket = self.active_connections.get(agent_id)
        if not websocket:
            logger.warning(
                "Failed to send JSON: Agent [%s] is offline.",
                agent_id,
            )
            return False

        try:
            await websocket.send_json(payload)
            return True
        except Exception as exc:
            logger.error(
                "Error dispatching JSON to agent [%s]: %s",
                agent_id,
                exc,
            )
            self.disconnect(agent_id)
            return False


# Global Singleton Instance
ws_manager = ConnectionManager()