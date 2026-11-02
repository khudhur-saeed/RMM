import asyncio
import hashlib
import uuid

from fastapi.testclient import TestClient

from app.core.config import settings
from app.db.session import async_session_factory, engine
from app.main import app
from app.models.agent import Agent
from app.models.organization import Organization
from app.models.site import Site

from conftest import delete_organizations, reset_shared_async_resources


async def _seed_inventory_test_agent(agent_id: uuid.UUID, api_key_hash: str) -> uuid.UUID:
    async with async_session_factory() as session:
        org = Organization(name=f"Inventory Org {uuid.uuid4().hex[:6]}")
        session.add(org)
        await session.flush()

        site = Site(name=f"Inventory Site {uuid.uuid4().hex[:6]}", org_id=org.id)
        session.add(site)
        await session.flush()

        agent = Agent(
            id=agent_id,
            site_id=site.id,
            hostname="INV-TEST-HOST",
            os="linux/amd64",
            private_ip="10.10.0.25",
            public_ip="127.0.0.1",
            api_key_hash=api_key_hash,
        )
        session.add(agent)
        await session.commit()

    await engine.dispose()
    return org.id


async def _cleanup_inventory_test_org(org_id: uuid.UUID) -> None:
    await delete_organizations([org_id])
    await engine.dispose()


def test_software_inventory_sync_and_search_pipeline():
    """
    Validates the Day 38 Software Inventory Sync Pipeline:
    1. Ingests a `software_inventory` frame over the C2 WebSocket and persists to PostgreSQL.
    2. Queries `GET /api/v1/agents/{agent_id}/software` and verifies alphabetical ordering.
    3. Tests case-insensitive substring search (`?search=`) across name, publisher, and version.
    4. Dispatches an updated `software_inventory` frame and verifies atomic replacement of stale rows.
    """
    raw_api_key = f"rmm_inv_test_{uuid.uuid4().hex}"
    api_key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
    agent_id = uuid.uuid4()

    org_id = asyncio.run(_seed_inventory_test_agent(agent_id, api_key_hash))
    auth_headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

    try:
        with TestClient(app) as client:
            ws_url = f"/api/v1/ws/agent/{agent_id}?token={raw_api_key}"
            op_url = f"/api/v1/ws/operator/{agent_id}?token={settings.ADMIN_API_TOKEN}"

            with client.websocket_connect(ws_url) as websocket:
                with client.websocket_connect(op_url) as op_ws:
                    # 1. Initial software inventory sync (3 packages + 1 duplicate)
                    websocket.send_json({
                        "type": "software_inventory",
                        "agent_id": str(agent_id),
                        "timestamp": 1700000100,
                        "software": [
                            {
                                "name": "PostgreSQL Server",
                                "version": "16.4-1",
                                "publisher": "PostgreSQL Global Development Group",
                                "install_date": "2026-09-01",
                            },
                            {
                                "name": "Docker Engine",
                                "version": "27.1.2",
                                "publisher": "Docker Inc.",
                                "install_date": "2026-08-15",
                            },
                            {
                                "name": "OpenSSH Server",
                                "version": "9.6p1",
                                "publisher": "OpenBSD Project",
                                "install_date": "2026-07-10",
                            },
                            {
                                "name": "Docker Engine",
                                "version": "27.1.2",
                                "publisher": "Docker Inc.",
                                "install_date": "2026-08-15",
                            },
                        ],
                    })

                    # Synchronize frame processing via operator echo
                    websocket.send_json({"type": "term_out", "payload": "INV_SYNC_1"})
                    assert op_ws.receive_text() == "INV_SYNC_1"

                    # 2. Verify full catalog persisted and ordered alphabetically
                    all_resp = client.get(
                        f"/api/v1/agents/{agent_id}/software", headers=auth_headers
                    )
                    assert all_resp.status_code == 200
                    items = all_resp.json()
                    assert len(items) == 3
                    assert [i["name"] for i in items] == [
                        "Docker Engine",
                        "OpenSSH Server",
                        "PostgreSQL Server",
                    ]

                    # 3. Verify substring search by publisher ("OpenBSD") and version ("16.4")
                    search_pub = client.get(
                        f"/api/v1/agents/{agent_id}/software?search=openbsd",
                        headers=auth_headers,
                    )
                    assert search_pub.status_code == 200
                    pub_items = search_pub.json()
                    assert len(pub_items) == 1
                    assert pub_items[0]["name"] == "OpenSSH Server"

                    search_ver = client.get(
                        f"/api/v1/agents/{agent_id}/software?search=16.4",
                        headers=auth_headers,
                    )
                    assert search_ver.status_code == 200
                    ver_items = search_ver.json()
                    assert len(ver_items) == 1
                    assert ver_items[0]["name"] == "PostgreSQL Server"

                    # 4. Dispatch updated inventory frame (atomic replacement)
                    websocket.send_json({
                        "type": "software_inventory",
                        "agent_id": str(agent_id),
                        "timestamp": 1700000200,
                        "software": [
                            {
                                "name": "Wireshark",
                                "version": "4.2.5",
                                "publisher": "Wireshark Foundation",
                                "install_date": "2026-10-20",
                            }
                        ],
                    })
                    websocket.send_json({"type": "term_out", "payload": "INV_SYNC_2"})
                    assert op_ws.receive_text() == "INV_SYNC_2"

                    updated_resp = client.get(
                        f"/api/v1/agents/{agent_id}/software", headers=auth_headers
                    )
                    assert updated_resp.status_code == 200
                    updated_items = updated_resp.json()
                    assert len(updated_items) == 1
                    assert updated_items[0]["name"] == "Wireshark"
    finally:
        reset_shared_async_resources()
        asyncio.run(_cleanup_inventory_test_org(org_id))
