import uuid
from typing import Iterable

import pytest
import redis.asyncio as redis
from sqlalchemy import delete

from app.core.config import settings
from app.core.ws_manager import ws_manager
from app.db.session import async_session_factory, engine
from app.models.organization import Organization


def reset_shared_async_resources() -> None:
    """
    The SQLAlchemy engine and the Redis client are module-level singletons.
    Their pooled connections are bound to the event loop that opened them, and
    each test (plus TestClient) runs on its own loop. Drop the stale pools
    without touching their sockets so the next loop opens fresh connections.
    """
    engine.sync_engine.dispose(close=False)
    ws_manager.redis_client = redis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
    )


@pytest.fixture(autouse=True)
def fresh_async_resources():
    """Rebind shared async clients to a clean state around every test."""
    reset_shared_async_resources()
    yield
    reset_shared_async_resources()


async def delete_organizations(org_ids: Iterable[uuid.UUID]) -> None:
    """Removes test tenants; sites, agents and tokens follow via ON DELETE CASCADE."""
    async with async_session_factory() as session:
        await session.execute(delete(Organization).where(Organization.id.in_(list(org_ids))))
        await session.commit()
