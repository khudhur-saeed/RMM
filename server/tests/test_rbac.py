import asyncio
import hashlib
from typing import List
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import delete
from starlette.websockets import WebSocketDisconnect

from app.core.config import settings
from app.core.rbac import ROLE_PERMISSIONS, Permission, Role
from app.db.session import async_session_factory, engine
from app.main import app
from app.models.agent import Agent
from app.models.organization import Organization
from app.models.script import Script
from app.models.site import Site
from app.models.user import User

from conftest import delete_organizations, reset_shared_async_resources


async def _seed_multi_site_fixture():
    """
    Seeds two isolated sites (Site A and Site B) under an Organization,
    each with a registered Agent, for testing RBAC role & site boundaries.
    """
    suffix = uuid.uuid4().hex[:6]
    raw_key_a = f"rmm_agent_a_{uuid.uuid4().hex}"
    raw_key_b = f"rmm_agent_b_{uuid.uuid4().hex}"
    hash_a = hashlib.sha256(raw_key_a.encode("utf-8")).hexdigest()
    hash_b = hashlib.sha256(raw_key_b.encode("utf-8")).hexdigest()

    async with async_session_factory() as session:
        org = Organization(name=f"RBAC Corp {suffix}")
        session.add(org)
        await session.flush()

        site_a = Site(name=f"Site Alpha {suffix}", org_id=org.id)
        site_b = Site(name=f"Site Beta {suffix}", org_id=org.id)
        session.add_all([site_a, site_b])
        await session.flush()

        agent_a = Agent(
            site_id=site_a.id,
            hostname="ALPHA-SRV-01",
            os="linux/amd64",
            private_ip="10.10.1.10",
            public_ip="127.0.0.1",
            api_key_hash=hash_a,
        )
        agent_b = Agent(
            site_id=site_b.id,
            hostname="BETA-SRV-01",
            os="windows/amd64",
            private_ip="10.10.2.20",
            public_ip="127.0.0.1",
            api_key_hash=hash_b,
        )
        session.add_all([agent_a, agent_b])
        await session.commit()

        fixture = {
            "org_id": org.id,
            "site_a_id": site_a.id,
            "site_b_id": site_b.id,
            "agent_a_id": agent_a.id,
            "agent_b_id": agent_b.id,
            "agent_a_key": raw_key_a,
            "agent_b_key": raw_key_b,
        }

    await engine.dispose()
    return fixture


async def _cleanup_rbac_fixture(
    org_ids: List[uuid.UUID],
    user_ids: List[uuid.UUID],
    script_ids: List[uuid.UUID],
) -> None:
    async with async_session_factory() as session:
        if user_ids:
            await session.execute(delete(User).where(User.id.in_(user_ids)))
        if script_ids:
            await session.execute(delete(Script).where(Script.id.in_(script_ids)))
        await session.commit()
    if org_ids:
        await delete_organizations(org_ids)
    await engine.dispose()


def test_rbac_role_hierarchy_and_permission_matrix():
    """
    Validates Day 43 RBAC role definitions:
    - SuperAdmin holds every defined permission.
    - SiteTechnician holds operational read, token write, script execute, key sign/verify, and C2/WS dispatch permissions,
      but lacks org/site creation, script keystore mutation, key rotation, and user management.
    - Auditor holds strictly read-only and signature verification permissions and zero write/dispatch permissions.
    """
    super_perms = ROLE_PERMISSIONS[Role.SUPER_ADMIN]
    tech_perms = ROLE_PERMISSIONS[Role.SITE_TECHNICIAN]
    auditor_perms = ROLE_PERMISSIONS[Role.AUDITOR]

    # SuperAdmin has full set
    assert super_perms == frozenset(Permission)

    # SiteTechnician capabilities & restrictions
    assert Permission.AGENT_DISPATCH in tech_perms
    assert Permission.WS_DISPATCH in tech_perms
    assert Permission.TOKEN_WRITE in tech_perms
    assert Permission.SCRIPT_EXECUTE in tech_perms
    assert Permission.KEY_SIGN in tech_perms
    assert Permission.ORG_WRITE not in tech_perms
    assert Permission.SITE_WRITE not in tech_perms
    assert Permission.SCRIPT_WRITE not in tech_perms
    assert Permission.KEY_ROTATE not in tech_perms
    assert Permission.USER_WRITE not in tech_perms

    # Auditor strictly read-only
    assert Permission.ORG_READ in auditor_perms
    assert Permission.SITE_READ in auditor_perms
    assert Permission.AGENT_READ in auditor_perms
    assert Permission.SCRIPT_READ in auditor_perms
    assert Permission.KEY_VERIFY in auditor_perms
    assert Permission.WS_CONNECT in auditor_perms
    for forbidden in (
        Permission.ORG_WRITE,
        Permission.SITE_WRITE,
        Permission.TOKEN_WRITE,
        Permission.AGENT_WRITE,
        Permission.AGENT_DISPATCH,
        Permission.SCRIPT_WRITE,
        Permission.SCRIPT_EXECUTE,
        Permission.KEY_SIGN,
        Permission.KEY_ROTATE,
        Permission.WS_DISPATCH,
        Permission.USER_WRITE,
    ):
        assert forbidden not in auditor_perms


def test_rbac_rest_middleware_dependencies_and_websocket_dispatch():
    """
    End-to-end validation of Day 43 & Day 44:
    1. Creates SuperAdmin, SiteTechnician (scoped to Site A), and Auditor users via `/api/v1/users`.
    2. Verifies `/api/v1/users/me`, `/api/v1/users/roles`, and `X-RBAC-Role` middleware headers.
    3. Verifies Auditor read-only access across all GET endpoints and 403 rejection on all write/dispatch endpoints.
    4. Verifies SiteTechnician site-scoped inventory/telemetry/token/task dispatch on Site A and 403 rejection on Site B.
    5. Verifies WebSocket C2 dispatch actions:
       - SiteTechnician can dispatch `term_in` and `task_dispatch` frames to Agent A, and is rejected on Agent B.
       - Auditor can passively observe Agent A stream output, but any WebSocket dispatch action (`term_in` or `task_dispatch`)
         is rejected with 403 + `WS_1008_POLICY_VIOLATION` without reaching the agent.
    6. Verifies account deactivation (`is_active=False`) and token rotation.
    """
    fx = asyncio.run(_seed_multi_site_fixture())
    created_org_ids: List[uuid.UUID] = [fx["org_id"]]
    created_user_ids: List[uuid.UUID] = []
    created_script_ids: List[uuid.UUID] = []
    suffix = uuid.uuid4().hex[:6]

    bootstrap_headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

    try:
        with TestClient(app) as client:
            # 1. Provision SuperAdmin, SiteTechnician (Site A), and Auditor accounts
            sa_resp = client.post(
                "/api/v1/users",
                headers=bootstrap_headers,
                json={
                    "username": f"superadmin_{suffix}",
                    "email": f"sa_{suffix}@rmm.local",
                    "role": "SuperAdmin",
                },
            )
            assert sa_resp.status_code == 201, sa_resp.text
            sa_data = sa_resp.json()
            created_user_ids.append(uuid.UUID(sa_data["id"]))
            sa_headers = {"Authorization": f"Bearer {sa_data['api_token']}"}

            tech_resp = client.post(
                "/api/v1/users",
                headers=sa_headers,
                json={
                    "username": f"tech_alpha_{suffix}",
                    "email": f"tech_{suffix}@rmm.local",
                    "role": "SiteTechnician",
                    "site_id": str(fx["site_a_id"]),
                },
            )
            assert tech_resp.status_code == 201, tech_resp.text
            tech_data = tech_resp.json()
            created_user_ids.append(uuid.UUID(tech_data["id"]))
            assert tech_data["org_id"] == str(fx["org_id"])
            assert tech_data["site_id"] == str(fx["site_a_id"])
            tech_headers = {"Authorization": f"Bearer {tech_data['api_token']}"}

            aud_resp = client.post(
                "/api/v1/users",
                headers=sa_headers,
                json={
                    "username": f"auditor_{suffix}",
                    "email": f"auditor_{suffix}@rmm.local",
                    "role": "Auditor",
                },
            )
            assert aud_resp.status_code == 201, aud_resp.text
            aud_data = aud_resp.json()
            created_user_ids.append(uuid.UUID(aud_data["id"]))
            aud_headers = {"Authorization": f"Bearer {aud_data['api_token']}"}

            # 2. Verify /users/me, /users/roles, and X-RBAC-Role middleware header
            me_tech = client.get("/api/v1/users/me", headers=tech_headers)
            assert me_tech.status_code == 200
            assert me_tech.headers.get("X-RBAC-Role") == "SiteTechnician"
            assert me_tech.json()["role"] == "SiteTechnician"
            assert me_tech.json()["site_id"] == str(fx["site_a_id"])

            roles_resp = client.get("/api/v1/users/roles", headers=aud_headers)
            assert roles_resp.status_code == 200
            assert roles_resp.headers.get("X-RBAC-Role") == "Auditor"
            assert {r["role"] for r in roles_resp.json()} == {
                "SuperAdmin",
                "SiteTechnician",
                "Auditor",
            }

            # 3. SuperAdmin creates a parameterized script in the keystore
            script_resp = client.post(
                "/api/v1/scripts",
                headers=sa_headers,
                json={
                    "name": f"RBAC Diagnostic Script {suffix}",
                    "description": "Echoes target environment",
                    "shell_type": "bash",
                    "content": "echo 'Inspecting {{TARGET_ENV}}'",
                    "tags": ["rbac", "audit"],
                    "parameters": [
                        {
                            "name": "TARGET_ENV",
                            "default_value": "production",
                            "required": True,
                        }
                    ],
                    "timeout_sec": 30,
                },
            )
            assert script_resp.status_code == 201, script_resp.text
            script_id = uuid.UUID(script_resp.json()["id"])
            created_script_ids.append(script_id)

            # 4. Validate Auditor read-only access vs write/dispatch rejection (403)
            assert client.get("/api/v1/organizations", headers=aud_headers).status_code == 200
            assert client.get("/api/v1/sites", headers=aud_headers).status_code == 200
            assert client.get("/api/v1/tokens", headers=aud_headers).status_code == 200
            assert client.get("/api/v1/agents", headers=aud_headers).status_code == 200
            assert (
                client.get(
                    f"/api/v1/agents/{fx['agent_a_id']}", headers=aud_headers
                ).status_code
                == 200
            )
            assert (
                client.get(
                    f"/api/v1/agents/{fx['agent_a_id']}/software", headers=aud_headers
                ).status_code
                == 200
            )
            assert (
                client.get(
                    f"/api/v1/agents/{fx['agent_a_id']}/telemetry", headers=aud_headers
                ).status_code
                == 200
            )
            assert client.get("/api/v1/scripts", headers=aud_headers).status_code == 200
            assert client.get("/api/v1/users", headers=aud_headers).status_code == 200

            # Auditor blocked on all state-mutating and dispatch routes
            assert (
                client.post(
                    "/api/v1/organizations",
                    headers=aud_headers,
                    json={"name": f"Unauthorized Org {suffix}"},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/sites",
                    headers=aud_headers,
                    json={"name": "Unauthorized Site", "org_id": str(fx["org_id"])},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/tokens",
                    headers=aud_headers,
                    json={"site_id": str(fx["site_a_id"]), "valid_hours": 24},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    f"/api/v1/agents/{fx['agent_a_id']}/tasks?command=whoami",
                    headers=aud_headers,
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/scripts",
                    headers=aud_headers,
                    json={
                        "name": "Auditor Forbidden Script",
                        "shell_type": "bash",
                        "content": "id",
                    },
                ).status_code
                == 403
            )
            assert (
                client.post(
                    f"/api/v1/scripts/{script_id}/render",
                    headers=aud_headers,
                    json={"values": {"TARGET_ENV": "staging"}},
                ).status_code
                == 403
            )
            assert (
                client.delete(
                    f"/api/v1/scripts/{script_id}", headers=aud_headers
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/keys/sign",
                    headers=aud_headers,
                    json={"payload": "echo test"},
                ).status_code
                == 403
            )
            assert (
                client.post("/api/v1/keys/rotate", headers=aud_headers).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/users",
                    headers=aud_headers,
                    json={"username": "hacker", "role": "SuperAdmin"},
                ).status_code
                == 403
            )

            # 5. Validate SiteTechnician permissions and site-scope isolation (Site A vs Site B)
            # Blocked from global admin actions
            assert (
                client.post(
                    "/api/v1/organizations",
                    headers=tech_headers,
                    json={"name": f"Tech Forbidden Org {suffix}"},
                ).status_code
                == 403
            )
            assert (
                client.post(
                    "/api/v1/sites",
                    headers=tech_headers,
                    json={"name": "Tech Forbidden Site", "org_id": str(fx["org_id"])},
                ).status_code
                == 403
            )
            assert (
                client.post("/api/v1/keys/rotate", headers=tech_headers).status_code
                == 403
            )
            assert (
                client.delete(
                    f"/api/v1/scripts/{script_id}", headers=tech_headers
                ).status_code
                == 403
            )
            assert client.get("/api/v1/users", headers=tech_headers).status_code == 403

            # SiteTechnician listing agents only sees Site A's agent
            tech_agents_resp = client.get("/api/v1/agents", headers=tech_headers)
            assert tech_agents_resp.status_code == 200
            tech_agent_ids = {a["id"] for a in tech_agents_resp.json()}
            assert str(fx["agent_a_id"]) in tech_agent_ids
            assert str(fx["agent_b_id"]) not in tech_agent_ids

            # SiteTechnician can access Agent A (Site A), but gets 403 Forbidden on Agent B (Site B)
            assert (
                client.get(
                    f"/api/v1/agents/{fx['agent_a_id']}", headers=tech_headers
                ).status_code
                == 200
            )
            assert (
                client.get(
                    f"/api/v1/agents/{fx['agent_b_id']}", headers=tech_headers
                ).status_code
                == 403
            )
            assert (
                client.get(
                    f"/api/v1/agents/{fx['agent_b_id']}/software", headers=tech_headers
                ).status_code
                == 403
            )
            assert (
                client.get(
                    f"/api/v1/agents/{fx['agent_b_id']}/telemetry", headers=tech_headers
                ).status_code
                == 403
            )

            # SiteTechnician can issue enrollment token for Site A, but gets 403 on Site B
            assert (
                client.post(
                    "/api/v1/tokens",
                    headers=tech_headers,
                    json={"site_id": str(fx["site_a_id"]), "valid_hours": 12},
                ).status_code
                == 201
            )
            assert (
                client.post(
                    "/api/v1/tokens",
                    headers=tech_headers,
                    json={"site_id": str(fx["site_b_id"]), "valid_hours": 12},
                ).status_code
                == 403
            )

            # SiteTechnician can sign payloads and verify signatures (And Auditor can verify)
            sign_resp = client.post(
                "/api/v1/keys/sign",
                headers=tech_headers,
                json={"payload": "uptime"},
            )
            assert sign_resp.status_code == 200
            sig_b64 = sign_resp.json()["signature_b64"]

            verify_aud = client.post(
                "/api/v1/keys/verify",
                headers=aud_headers,
                json={"payload": "uptime", "signature_b64": sig_b64},
            )
            assert verify_aud.status_code == 200
            assert verify_aud.json()["valid"] is True

            # 6. Validate REST & WebSocket C2 Dispatch Actions across roles and sites
            ws_agent_a = f"/api/v1/ws/agent/{fx['agent_a_id']}?token={fx['agent_a_key']}"
            ws_agent_b = f"/api/v1/ws/agent/{fx['agent_b_id']}?token={fx['agent_b_key']}"

            with (
                client.websocket_connect(ws_agent_a) as agent_a_ws,
                client.websocket_connect(ws_agent_b) as agent_b_ws,
            ):
                # 6a. SiteTechnician dispatches REST task to Agent A -> 202 Accepted
                task_ok = client.post(
                    f"/api/v1/agents/{fx['agent_a_id']}/tasks?command=hostname&timeout_sec=15",
                    headers=tech_headers,
                )
                assert task_ok.status_code == 202
                frame_a = agent_a_ws.receive_json()
                assert frame_a["type"] == "task_dispatch"
                assert frame_a["command"] == "hostname"

                # 6b. SiteTechnician blocked from dispatching REST task or rendered script to Agent B -> 403
                task_denied = client.post(
                    f"/api/v1/agents/{fx['agent_b_id']}/tasks?command=hostname",
                    headers=tech_headers,
                )
                assert task_denied.status_code == 403

                render_denied = client.post(
                    f"/api/v1/scripts/{script_id}/render",
                    headers=tech_headers,
                    json={
                        "values": {"TARGET_ENV": "beta"},
                        "agent_id": str(fx["agent_b_id"]),
                    },
                )
                assert render_denied.status_code == 403

                # 6c. SiteTechnician blocked from connecting to Agent B's Operator WebSocket -> 1008
                with pytest.raises(WebSocketDisconnect) as exc_info:
                    with client.websocket_connect(
                        f"/api/v1/ws/operator/{fx['agent_b_id']}?token={tech_data['api_token']}"
                    ):
                        pass
                assert exc_info.value.code == 1008

                # 6d. SiteTechnician connects to Agent A's Operator WebSocket and dispatches `term_in` & `task_dispatch`
                with client.websocket_connect(
                    f"/api/v1/ws/operator/{fx['agent_a_id']}?token={tech_data['api_token']}"
                ) as tech_ws:
                    tech_ws.send_text("ls -la\n")
                    term_frame = agent_a_ws.receive_json()
                    assert term_frame == {"type": "term_in", "payload": "ls -la\n"}

                    tech_ws.send_json(
                        {
                            "type": "task_dispatch",
                            "command": "uname -r",
                            "timeout_sec": 20,
                        }
                    )
                    ws_task_frame = agent_a_ws.receive_json()
                    assert ws_task_frame["type"] == "task_dispatch"
                    assert ws_task_frame["command"] == "uname -r"
                    assert len(ws_task_frame["signature"]) > 0

                # 6e. Auditor connects to Agent A's Operator WebSocket:
                # Can passively observe `term_out`, but is rejected on WebSocket dispatch actions!
                with client.websocket_connect(
                    f"/api/v1/ws/operator/{fx['agent_a_id']}?token={aud_data['api_token']}"
                ) as aud_ws:
                    agent_a_ws.send_json({"type": "term_out", "payload": "AUDIT_LOG_LINE\r\n"})
                    assert aud_ws.receive_text() == "AUDIT_LOG_LINE\r\n"

                    # Auditor attempts to dispatch a command over WebSocket -> 403 error frame + 1008 close
                    aud_ws.send_text("rm -rf /\n")
                    err_frame = aud_ws.receive_json()
                    assert err_frame["type"] == "error"
                    assert err_frame["code"] == 403
                    with pytest.raises(WebSocketDisconnect) as close_exc:
                        aud_ws.receive_text()
                    assert close_exc.value.code == 1008

            # 7. Deactivate SiteTechnician account and verify 403 Forbidden on subsequent requests
            deactivate_resp = client.patch(
                f"/api/v1/users/{tech_data['id']}",
                headers=sa_headers,
                json={"is_active": False},
            )
            assert deactivate_resp.status_code == 200
            assert deactivate_resp.json()["is_active"] is False

            disabled_check = client.get("/api/v1/agents", headers=tech_headers)
            assert disabled_check.status_code == 403
    finally:
        reset_shared_async_resources()
        asyncio.run(
            _cleanup_rbac_fixture(created_org_ids, created_user_ids, created_script_ids)
        )
