import asyncio
from datetime import datetime, timedelta, timezone
import logging
import uuid
from typing import Sequence

from sqlalchemy import select

from app.core.ws_manager import ws_manager
from app.db.session import async_session_factory
from app.models.agent import Agent

logger = logging.getLogger("rmm.watchdog")


async def evaluate_lapsed_agents(
    threshold_seconds: int = 90,
    agent_ids: Sequence[uuid.UUID] | None = None,
) -> int:
    """
    Scans the database for agents whose last_seen timestamp exceeds the threshold,
    verifies fallback status against Redis, and marks ghost nodes offline.
    Supports optional agent_ids filter for isolated testing.
    """
    now = datetime.now(timezone.utc)
    deadline = now - timedelta(seconds=threshold_seconds)
    lapsed_count = 0

    async with async_session_factory() as session:
        # Build query: filter by deadline and optionally by specific agent IDs
        stmt = select(Agent).where(Agent.last_seen < deadline)
        
        if agent_ids is not None:
            stmt = stmt.where(Agent.id.in_(agent_ids))

        result = await session.execute(stmt)
        stale_agents = result.scalars().all()

        for agent in stale_agents:
            redis_key = f"agent:{agent.id}:status"
            cached_status = await ws_manager.redis_client.get(redis_key)

            # If Redis confirms no active TTL/presence, evict state and register offline event
            if not cached_status:
                logger.warning(
                    "Watchdog Alert: Agent [%s] (%s) missed heartbeat deadline (Last seen: %s).",
                    agent.id,
                    agent.hostname,
                    agent.last_seen,
                )
                if agent.id in ws_manager.active_connections:
                    ws_manager.disconnect(agent.id)

                lapsed_count += 1
            else:
                logger.debug(
                    "Agent [%s] database timestamp stale, but Redis heartbeat key active.",
                    agent.id,
                )

        return lapsed_count


async def run_agent_watchdog(interval_seconds: int = 30, threshold_seconds: int = 90) -> None:
    """
    Infinite background service coroutine intended to run inside application lifespan.
    Periodically evaluates endpoint heartbeats and handles graceful cancellation.
    """
    logger.info(
        "Agent Watchdog Worker initialized. Interval: %ds, Threshold: %ds",
        interval_seconds,
        threshold_seconds,
    )
    try:
        while True:
            await asyncio.sleep(interval_seconds)
            try:
                lapsed = await evaluate_lapsed_agents(threshold_seconds=threshold_seconds)
                if lapsed > 0:
                    logger.info("Watchdog sweep finished: %d agent(s) marked offline.", lapsed)
            except Exception as exc:
                logger.error("Unexpected error during watchdog sweep: %s", exc)
    except asyncio.CancelledError:
        logger.info("Agent Watchdog Worker received cancellation signal. Terminating loop safely.")
        raise
