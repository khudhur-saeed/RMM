import uuid
import pytest
from unittest.mock import AsyncMock
from app.core.ws_manager import ws_manager


@pytest.mark.asyncio
async def test_direct_ws_manager_redis_lifecycle():
    """
    Tests ConnectionManager local memory and Redis synchronization
    without event loop conflicts.
    """
    agent_id = uuid.uuid4()
    registry_key = str(agent_id).lower()  # ConnectionManager canonical key
    mock_socket = AsyncMock()
    redis_key = f"agent:{agent_id}:status"

    # 1. Connect agent: accept socket and write state to Redis
    await ws_manager.connect(agent_id, mock_socket)

    assert registry_key in ws_manager.active_connections
    mock_socket.accept.assert_awaited_once()

    status_val = await ws_manager.redis_client.get(redis_key)
    assert status_val == "online"

    ttl = await ws_manager.redis_client.ttl(redis_key)
    assert 0 < ttl <= 60

    # 2. Disconnect agent: remove from memory and purge key from Redis
    await ws_manager.disconnect(agent_id)

    assert registry_key not in ws_manager.active_connections
    status_post_disconnect = await ws_manager.redis_client.get(redis_key)
    assert status_post_disconnect is None