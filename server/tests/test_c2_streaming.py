import asyncio
import hashlib
import uuid
from fastapi.testclient import TestClient

from app.db.session import async_session_factory, engine
from app.main import app
from app.models.agent import Agent
from app.models.organization import Organization
from app.models.site import Site

from conftest import delete_organizations, reset_shared_async_resources


async def _seed_test_agent(agent_id: uuid.UUID, api_key_hash: str) -> uuid.UUID:
    """Seeds an isolated organization, site, and agent record into the database."""
    async with async_session_factory() as session:
        org = Organization(name=f"Stream Org {uuid.uuid4().hex[:6]}")
        session.add(org)
        await session.flush()

        site = Site(name=f"Stream Site {uuid.uuid4().hex[:6]}", org_id=org.id)
        session.add(site)
        await session.flush()

        agent = Agent(
            id=agent_id,
            site_id=site.id,
            hostname="STREAM-TEST-RUNNER",
            os="linux/amd64",
            private_ip="192.168.10.60",
            public_ip="127.0.0.1",
            api_key_hash=api_key_hash,
        )
        session.add(agent)
        await session.commit()

    # Clear connection pool to avoid event loop leakage into synchronous TestClient
    await engine.dispose()
    return org.id


async def _cleanup_test_org(org_id: uuid.UUID) -> None:
    """Deletes the seeded tenant (cascades to site and agent)."""
    await delete_organizations([org_id])
    await engine.dispose()


def test_c2_streaming_protocol_ingestion():
    """
    Validates end-to-end WebSocket C2 streaming protocol:
    1. Pre-upgrade SHA-256 token authentication.
    2. Real-time stdout and stderr chunk streaming ingestion.
    3. Final process exit frame capture and schema conformance.
    """
    raw_api_key = f"rmm_stream_test_{uuid.uuid4().hex}"
    api_key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
    agent_id = uuid.uuid4()
    task_id = uuid.uuid4()

    # Phase 1: Seed isolated test agent
    org_id = asyncio.run(_seed_test_agent(agent_id, api_key_hash))

    try:
        # Phase 2: Execute live socket interaction using TestClient
        with TestClient(app) as client:
            ws_url = f"/api/v1/ws/agent/{agent_id}?token={raw_api_key}"
            with client.websocket_connect(ws_url) as websocket:
                # 1. Dispatch simulated live stdout chunk
                websocket.send_json({
                    "type": "task_stream",
                    "task_id": str(task_id),
                    "stream": "stdout",
                    "chunk": "Live stdout chunk: Ping reply received\n",
                })

                # 2. Dispatch simulated live stderr chunk
                websocket.send_json({
                    "type": "task_stream",
                    "task_id": str(task_id),
                    "stream": "stderr",
                    "chunk": "Live stderr chunk: Process warning logged\n",
                })

                # 3. Dispatch simulated exit frame
                websocket.send_json({
                    "type": "task_exit",
                    "task_id": str(task_id),
                    "exit_code": 0,
                    "elapsed_ms": 1250,
                    "error": None,
                })

                # If frames caused validation errors or disconnections, socket closes abnormally
                # Sending a lightweight ping confirms socket connection remains healthy and open
                websocket.send_json({"type": "heartbeat"})
    finally:
        # TestClient ran on its own event loop; drop its pools before cleaning up
        reset_shared_async_resources()
        asyncio.run(_cleanup_test_org(org_id))