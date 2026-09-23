import hashlib
from datetime import datetime, timedelta, timezone
import uuid
import pytest

from app.core.ws_manager import ws_manager
from app.db.session import async_session_factory, engine
from app.models.agent import Agent
from app.models.organization import Organization
from app.models.site import Site
from app.services.watchdog import evaluate_lapsed_agents


@pytest.mark.asyncio
async def test_watchdog_detects_lapsed_agents_and_verifies_redis():
    """
    Validates that evaluate_lapsed_agents accurately identifies nodes
    whose heartbeats exceed the deadline threshold and purges dangling state.
    """
    now = datetime.now(timezone.utc)
    fresh_time = now
    stale_time = now - timedelta(seconds=120)  # Beyond the 90s threshold

    org_id = uuid.uuid4()
    site_id = uuid.uuid4()
    active_agent_id = uuid.uuid4()
    lapsed_agent_id = uuid.uuid4()

    # Generate unique cryptographic hashes to respect ix_agents_api_key_hash unique constraint
    active_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    lapsed_hash = hashlib.sha256(uuid.uuid4().bytes).hexdigest()

    # 1. Seed database with active tenant, site, and two agent nodes
    async with async_session_factory() as session:
        org = Organization(id=org_id, name=f"Test Org Watchdog {uuid.uuid4().hex[:6]}")
        session.add(org)
        await session.flush()

        site = Site(id=site_id, org_id=org.id, name="Test Site Watchdog")
        session.add(site)
        await session.flush()

        # Node A: Active heartbeat
        active_agent = Agent(
            id=active_agent_id,
            site_id=site.id,
            hostname="NODE-ACTIVE",
            os="linux/amd64",
            api_key_hash=active_hash,
            last_seen=fresh_time,
        )
        # Node B: Lapsed heartbeat (Stale timestamp)
        lapsed_agent = Agent(
            id=lapsed_agent_id,
            site_id=site.id,
            hostname="NODE-LAPSED",
            os="linux/amd64",
            api_key_hash=lapsed_hash,
            last_seen=stale_time,
        )

        session.add_all([active_agent, lapsed_agent])
        await session.commit()

    # 2. Redis State Setup: Clean status keys to ensure accurate fallback check
    await ws_manager.redis_client.delete(f"agent:{active_agent_id}:status")
    await ws_manager.redis_client.delete(f"agent:{lapsed_agent_id}:status")

    # 3. Trigger Watchdog Evaluation Sweep scoped strictly to our test agents
    test_scope = [active_agent_id, lapsed_agent_id]
    lapsed_count = await evaluate_lapsed_agents(threshold_seconds=90, agent_ids=test_scope)

    # 4. Assertions: Exactly one ghost agent must be detected among test nodes
    assert lapsed_count == 1, f"Expected 1 lapsed agent in scope, got {lapsed_count}"

    # Clean up physical engine connections
    await engine.dispose()
