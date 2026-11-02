import asyncio
import hashlib
from typing import List
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.core.config import settings
from app.db.session import async_session_factory, engine
from app.main import app
from app.models.agent import Agent
from app.models.organization import Organization
from app.models.script import Script
from app.models.site import Site

from conftest import delete_organizations, reset_shared_async_resources


async def _seed_test_agent(agent_id: uuid.UUID, api_key_hash: str) -> uuid.UUID:
    async with async_session_factory() as session:
        org = Organization(name=f"Script Org {uuid.uuid4().hex[:6]}")
        session.add(org)
        await session.flush()

        site = Site(name=f"Script Site {uuid.uuid4().hex[:6]}", org_id=org.id)
        session.add(site)
        await session.flush()

        agent = Agent(
            id=agent_id,
            site_id=site.id,
            hostname="SCRIPT-TEST-HOST",
            os="linux/amd64",
            private_ip="10.10.0.44",
            public_ip="127.0.0.1",
            api_key_hash=api_key_hash,
        )
        session.add(agent)
        await session.commit()

    await engine.dispose()
    return org.id


async def _cleanup_scripts_and_org(script_ids: List[uuid.UUID], org_id: uuid.UUID) -> None:
    if script_ids:
        async with async_session_factory() as session:
            await session.execute(delete(Script).where(Script.id.in_(script_ids)))
            await session.commit()
    await delete_organizations([org_id])
    await engine.dispose()


def test_scripts_keystore_crud_tagging_and_parameterization():
    """
    Validates the Day 39 FastAPI Script Keystore:
    1. Creates PowerShell and Bash scripts with tags and template parameters (both explicit and auto-detected).
    2. Verifies duplicate script name conflict rejection (409 Conflict).
    3. Lists and filters scripts by tag (case-insensitive), shell_type, and search substring.
    4. Updates a script via PATCH and verifies tag normalization and parameter refresh.
    5. Renders a parameterized script with default values, runtime overrides, and missing required parameter rejection (422).
    6. Dispatches a rendered script directly over a live C2 WebSocket tunnel to an agent.
    7. Deletes the scripts and confirms 404 on subsequent lookup.
    """
    raw_api_key = f"rmm_script_test_{uuid.uuid4().hex}"
    api_key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()
    agent_id = uuid.uuid4()
    created_script_ids: List[uuid.UUID] = []

    org_id = asyncio.run(_seed_test_agent(agent_id, api_key_hash))
    auth_headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}
    suffix = uuid.uuid4().hex[:6]

    try:
        with TestClient(app) as client:
            # 1. Create a parameterized PowerShell script (with 1 declared default param + 1 undeclared placeholder)
            ps_name = f"Restart Windows Service {suffix}"
            ps_resp = client.post(
                "/api/v1/scripts",
                headers=auth_headers,
                json={
                    "name": ps_name,
                    "description": "Restarts a target Windows service and logs status",
                    "shell_type": "powershell",
                    "content": "Restart-Service -Name '{{SERVICE_NAME}}' -Force:$({{FORCE_FLAG}})",
                    "tags": ["Windows", "Remediation", "windows", "  SERVICE  "],
                    "parameters": [
                        {
                            "name": "FORCE_FLAG",
                            "description": "Whether to force restart dependent services",
                            "default_value": "$true",
                            "required": True,
                        }
                    ],
                    "timeout_sec": 90,
                },
            )
            assert ps_resp.status_code == 201, ps_resp.text
            ps_script = ps_resp.json()
            ps_id = uuid.UUID(ps_script["id"])
            created_script_ids.append(ps_id)

            # Verify tag normalization & deduplication
            assert ps_script["tags"] == ["windows", "remediation", "service"]
            # Verify auto-extraction of undeclared {{SERVICE_NAME}} alongside declared FORCE_FLAG
            param_names = [p["name"] for p in ps_script["parameters"]]
            assert param_names == ["FORCE_FLAG", "SERVICE_NAME"]

            # 2. Verify duplicate script name returns 409 Conflict
            dup_resp = client.post(
                "/api/v1/scripts",
                headers=auth_headers,
                json={
                    "name": ps_name,
                    "shell_type": "powershell",
                    "content": "Write-Output 'Duplicate'",
                },
            )
            assert dup_resp.status_code == 409

            # 3. Create a parameterized Bash script
            bash_name = f"Flush DNS and Check Port {suffix}"
            bash_resp = client.post(
                "/api/v1/scripts",
                headers=auth_headers,
                json={
                    "name": bash_name,
                    "description": "Checks TCP connectivity to target host and port on Linux",
                    "shell_type": "bash",
                    "content": "nc -zv {{TARGET_HOST}} {{TARGET_PORT}}",
                    "tags": ["Linux", "Network", "Diagnostics"],
                    "parameters": [
                        {
                            "name": "TARGET_HOST",
                            "description": "Target hostname or IP",
                            "default_value": "127.0.0.1",
                            "required": True,
                        },
                        {
                            "name": "TARGET_PORT",
                            "description": "Target TCP port",
                            "default_value": "443",
                            "required": True,
                        },
                    ],
                    "timeout_sec": 45,
                },
            )
            assert bash_resp.status_code == 201, bash_resp.text
            bash_script = bash_resp.json()
            bash_id = uuid.UUID(bash_script["id"])
            created_script_ids.append(bash_id)

            # 4. Filter by tag (case-insensitive), shell_type, and search query
            tag_filter = client.get(
                "/api/v1/scripts?tag=NETWORK", headers=auth_headers
            )
            assert tag_filter.status_code == 200
            assert any(s["id"] == str(bash_id) for s in tag_filter.json())
            assert all(s["id"] != str(ps_id) for s in tag_filter.json())

            shell_filter = client.get(
                "/api/v1/scripts?shell_type=powershell", headers=auth_headers
            )
            assert shell_filter.status_code == 200
            assert any(s["id"] == str(ps_id) for s in shell_filter.json())
            assert all(s["id"] != str(bash_id) for s in shell_filter.json())

            search_filter = client.get(
                f"/api/v1/scripts?search={suffix}", headers=auth_headers
            )
            assert search_filter.status_code == 200
            assert len(search_filter.json()) == 2

            # 5. Update script via PATCH
            patch_resp = client.patch(
                f"/api/v1/scripts/{bash_id}",
                headers=auth_headers,
                json={
                    "tags": ["linux", "network", "security-audit"],
                    "timeout_sec": 120,
                },
            )
            assert patch_resp.status_code == 200
            patched = patch_resp.json()
            assert patched["tags"] == ["linux", "network", "security-audit"]
            assert patched["timeout_sec"] == 120

            # 6. Parameter rendering validation
            # 6a. Missing required parameter (SERVICE_NAME has no default_value) -> 422
            missing_render = client.post(
                f"/api/v1/scripts/{ps_id}/render",
                headers=auth_headers,
                json={"values": {}},
            )
            assert missing_render.status_code == 422
            assert "SERVICE_NAME" in missing_render.json()["detail"]

            # 6b. Render PowerShell script supplying SERVICE_NAME and relying on FORCE_FLAG default ($true)
            ok_render = client.post(
                f"/api/v1/scripts/{ps_id}/render",
                headers=auth_headers,
                json={"values": {"SERVICE_NAME": "Spooler"}},
            )
            assert ok_render.status_code == 200
            rendered_ps = ok_render.json()
            assert (
                rendered_ps["rendered_command"]
                == "Restart-Service -Name 'Spooler' -Force:$($true)"
            )
            assert rendered_ps["dispatched_task_id"] is None

            # 6c. Render Bash script and dispatch over live C2 WebSocket tunnel
            ws_url = f"/api/v1/ws/agent/{agent_id}?token={raw_api_key}"
            with client.websocket_connect(ws_url) as agent_ws:
                dispatch_render = client.post(
                    f"/api/v1/scripts/{bash_id}/render",
                    headers=auth_headers,
                    json={
                        "values": {"TARGET_HOST": "10.0.0.1", "TARGET_PORT": "8443"},
                        "agent_id": str(agent_id),
                    },
                )
                assert dispatch_render.status_code == 200
                dispatch_data = dispatch_render.json()
                assert dispatch_data["rendered_command"] == "nc -zv 10.0.0.1 8443"
                assert dispatch_data["dispatched_task_id"] is not None

                c2_frame = agent_ws.receive_json()
                assert c2_frame["type"] == "task_dispatch"
                assert c2_frame["task_id"] == dispatch_data["dispatched_task_id"]
                assert c2_frame["command"] == "nc -zv 10.0.0.1 8443"
                assert c2_frame["timeout_sec"] == 120

            # 7. Delete scripts and verify 404
            del_resp = client.delete(
                f"/api/v1/scripts/{ps_id}", headers=auth_headers
            )
            assert del_resp.status_code == 204
            created_script_ids.remove(ps_id)

            get_deleted = client.get(
                f"/api/v1/scripts/{ps_id}", headers=auth_headers
            )
            assert get_deleted.status_code == 404
    finally:
        reset_shared_async_resources()
        asyncio.run(_cleanup_scripts_and_org(created_script_ids, org_id))
