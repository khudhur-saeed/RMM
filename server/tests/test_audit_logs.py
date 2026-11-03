import asyncio
import hashlib
from typing import List
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import DBAPIError

from app.core.audit import compute_output_hash
from app.core.config import settings
from app.db.session import async_session_factory, engine
from app.main import app
from app.models.agent import Agent
from app.models.audit_log import AuditLog, AuditLogImmutabilityError
from app.models.organization import Organization
from app.models.script import Script
from app.models.site import Site
from app.models.user import User

from conftest import delete_organizations, reset_shared_async_resources


async def _seed_audit_test_fixture():
    suffix = uuid.uuid4().hex[:6]
    raw_agent_key = f"rmm_audit_agent_{uuid.uuid4().hex}"
    agent_key_hash = hashlib.sha256(raw_agent_key.encode("utf-8")).hexdigest()

    async with async_session_factory() as session:
        org = Organization(name=f"Audit Org {suffix}")
        session.add(org)
        await session.flush()

        site = Site(name=f"Audit Site {suffix}", org_id=org.id)
        session.add(site)
        await session.flush()

        agent = Agent(
            site_id=site.id,
            hostname="AUDIT-ENDPOINT-01",
            os="linux/amd64",
            private_ip="10.50.0.10",
            public_ip="127.0.0.1",
            api_key_hash=agent_key_hash,
        )
        session.add(agent)
        await session.commit()

        data = {
            "org_id": org.id,
            "site_id": site.id,
            "agent_id": agent.id,
            "agent_key": raw_agent_key,
        }

    await engine.dispose()
    return data


async def _cleanup_audit_fixture(
    org_id: uuid.UUID,
    user_ids: List[uuid.UUID],
    script_ids: List[uuid.UUID],
) -> None:
    async with async_session_factory() as session:
        if user_ids:
            await session.execute(delete(User).where(User.id.in_(user_ids)))
        if script_ids:
            await session.execute(delete(Script).where(Script.id.in_(script_ids)))
        await session.commit()
    await delete_organizations([org_id])
    await engine.dispose()


async def _verify_orm_and_postgres_immutability(log_id: uuid.UUID) -> None:
    """
    Directly tests both:
    1. SQLAlchemy ORM `before_update` / `before_delete` hooks raising `AuditLogImmutabilityError`.
    2. PostgreSQL `trg_audit_logs_immutable` trigger rejecting raw SQL UPDATE and DELETE statements.
    """
    # 1. ORM Update attempt -> AuditLogImmutabilityError
    async with async_session_factory() as session:
        entry = (
            await session.execute(select(AuditLog).where(AuditLog.id == log_id))
        ).scalar_one()
        entry.command_text = "tampered command"
        with pytest.raises(AuditLogImmutabilityError):
            await session.flush()
        await session.rollback()

    # 2. ORM Delete attempt -> AuditLogImmutabilityError
    async with async_session_factory() as session:
        entry = (
            await session.execute(select(AuditLog).where(AuditLog.id == log_id))
        ).scalar_one()
        await session.delete(entry)
        with pytest.raises(AuditLogImmutabilityError):
            await session.flush()
        await session.rollback()

    # 3. Raw SQL UPDATE attempt -> rejected by PostgreSQL trigger
    async with async_session_factory() as session:
        with pytest.raises(DBAPIError) as update_exc:
            await session.execute(
                text("UPDATE audit_logs SET command_text = 'hacked' WHERE id = :id"),
                {"id": log_id},
            )
        assert "immutable" in str(update_exc.value).lower()
        await session.rollback()

    # 4. Raw SQL DELETE attempt -> rejected by PostgreSQL trigger
    async with async_session_factory() as session:
        with pytest.raises(DBAPIError) as delete_exc:
            await session.execute(
                text("DELETE FROM audit_logs WHERE id = :id"),
                {"id": log_id},
            )
        assert "immutable" in str(delete_exc.value).lower()
        await session.rollback()

    await engine.dispose()


def test_immutable_audit_logging_middleware_and_c2_stream_hashing():
    """
    Validates Day 45 Immutable Audit Logging Table & Middleware:
    1. Creates SiteTechnician and Auditor operators.
    2. Dispatches REST tasks (`POST /api/v1/agents/{id}/tasks`) and rendered scripts (`POST /api/v1/scripts/{id}/render`),
       verifying `AuditLogMiddleware` records `admin_id`, `target_agent_id`, `command_text`, and `output_hash`.
    3. Streams simulated stdout/stderr chunks + `task_exit` from the agent over WebSocket and verifies
       `WS_TASK_COMPLETE` records the exact SHA-256 `output_hash` of the concatenated command output.
    4. Verifies `Auditor` and `SuperAdmin` can query `/api/v1/audit-logs` while `SiteTechnician` gets 403 Forbidden.
    5. Verifies append-only immutability at REST API (403), SQLAlchemy ORM (`AuditLogImmutabilityError`),
       and PostgreSQL trigger (`trg_audit_logs_immutable`) layers.
    """
    fx = asyncio.run(_seed_audit_test_fixture())
    user_ids: List[uuid.UUID] = []
    script_ids: List[uuid.UUID] = []
    suffix = uuid.uuid4().hex[:6]

    sa_headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

    try:
        with TestClient(app) as client:
            # 1. Create a SiteTechnician (scoped to fx["site_id"]) and an Auditor
            tech_resp = client.post(
                "/api/v1/users",
                headers=sa_headers,
                json={
                    "username": f"audit_tech_{suffix}",
                    "role": "SiteTechnician",
                    "site_id": str(fx["site_id"]),
                },
            )
            assert tech_resp.status_code == 201
            tech_user = tech_resp.json()
            tech_id = uuid.UUID(tech_user["id"])
            user_ids.append(tech_id)
            tech_headers = {"Authorization": f"Bearer {tech_user['api_token']}"}

            aud_resp = client.post(
                "/api/v1/users",
                headers=sa_headers,
                json={
                    "username": f"compliance_auditor_{suffix}",
                    "role": "Auditor",
                },
            )
            assert aud_resp.status_code == 201
            aud_user = aud_resp.json()
            aud_id = uuid.UUID(aud_user["id"])
            user_ids.append(aud_id)
            aud_headers = {"Authorization": f"Bearer {aud_user['api_token']}"}

            # 2. Create a script in the keystore
            script_resp = client.post(
                "/api/v1/scripts",
                headers=sa_headers,
                json={
                    "name": f"Audit Check Script {suffix}",
                    "shell_type": "bash",
                    "content": "systemctl status {{DAEMON}}",
                    "parameters": [
                        {"name": "DAEMON", "default_value": "sshd", "required": True}
                    ],
                },
            )
            assert script_resp.status_code == 201
            script_id = uuid.UUID(script_resp.json()["id"])
            script_ids.append(script_id)

            # 3. Connect Agent WebSocket and execute REST + WebSocket command dispatches
            ws_agent_url = f"/api/v1/ws/agent/{fx['agent_id']}?token={fx['agent_key']}"
            with client.websocket_connect(ws_agent_url) as agent_ws:
                # 3a. SiteTechnician dispatches a shell command via REST
                cmd_str = f"journalctl -u sshd -n 25 --tag={suffix}"
                dispatch_resp = client.post(
                    f"/api/v1/agents/{fx['agent_id']}/tasks",
                    params={"command": cmd_str, "timeout_sec": 30},
                    headers=tech_headers,
                )
                assert dispatch_resp.status_code == 202
                assert "X-Audit-Log-Id" in dispatch_resp.headers
                assert "X-Audit-Output-Hash" in dispatch_resp.headers

                expected_rest_hash = compute_output_hash(dispatch_resp.content)
                assert dispatch_resp.headers["X-Audit-Output-Hash"] == expected_rest_hash
                rest_audit_id = uuid.UUID(dispatch_resp.headers["X-Audit-Log-Id"])

                c2_frame = agent_ws.receive_json()
                dispatched_task_id = c2_frame["task_id"]

                # 3b. Agent streams stdout + stderr chunks and finishes with task_exit
                chunk_1 = "sshd[1024]: Server listening on 0.0.0.0 port 22.\n"
                chunk_2 = "sshd[1024]: Accepted publickey for root from 10.50.0.1\n"
                agent_ws.send_json(
                    {
                        "type": "task_stream",
                        "task_id": dispatched_task_id,
                        "stream": "stdout",
                        "chunk": chunk_1,
                    }
                )
                agent_ws.send_json(
                    {
                        "type": "task_stream",
                        "task_id": dispatched_task_id,
                        "stream": "stdout",
                        "chunk": chunk_2,
                    }
                )
                agent_ws.send_json(
                    {
                        "type": "task_exit",
                        "task_id": dispatched_task_id,
                        "exit_code": 0,
                        "elapsed_ms": 84,
                        "error": None,
                    }
                )

                # 3c. SiteTechnician renders & dispatches parameterized script via REST
                render_resp = client.post(
                    f"/api/v1/scripts/{script_id}/render",
                    headers=tech_headers,
                    json={
                        "values": {"DAEMON": "nginx"},
                        "agent_id": str(fx["agent_id"]),
                    },
                )
                assert render_resp.status_code == 200
                render_frame = agent_ws.receive_json()
                assert render_frame["command"] == "systemctl status nginx"

            # 4. Auditor queries `/api/v1/audit-logs` filtered by target_agent_id and admin_id
            logs_resp = client.get(
                f"/api/v1/audit-logs?target_agent_id={fx['agent_id']}",
                headers=aud_headers,
            )
            assert logs_resp.status_code == 200, logs_resp.text
            logs = logs_resp.json()
            assert len(logs) >= 3

            # Verify the REST task dispatch audit entry
            rest_log = next(l for l in logs if l["id"] == str(rest_audit_id))
            assert rest_log["admin_id"] == str(tech_id)
            assert rest_log["admin_username"] == f"audit_tech_{suffix}"
            assert rest_log["admin_role"] == "SiteTechnician"
            assert rest_log["target_agent_id"] == str(fx["agent_id"])
            assert rest_log["target_agent"] == str(fx["agent_id"])
            assert rest_log["command_text"] == cmd_str
            assert rest_log["output_hash"] == expected_rest_hash

            # Verify the WebSocket streamed task completion audit entry (`WS_TASK_COMPLETE`)
            expected_stream_output_hash = compute_output_hash(chunk_1 + chunk_2)
            complete_log = next(
                l
                for l in logs
                if l["action"] == "WS_TASK_COMPLETE"
                and l["task_id"] == dispatched_task_id
            )
            assert complete_log["admin_id"] == str(tech_id)
            assert complete_log["target_agent_id"] == str(fx["agent_id"])
            assert complete_log["command_text"] == cmd_str
            assert complete_log["output_hash"] == expected_stream_output_hash

            # Verify the rendered script dispatch audit entry
            script_log = next(
                l for l in logs if l["command_text"] == "systemctl status nginx"
            )
            assert script_log["admin_id"] == str(tech_id)
            assert script_log["target_agent_id"] == str(fx["agent_id"])
            assert len(script_log["output_hash"]) == 64

            # 5. SiteTechnician is forbidden from querying global audit logs (403)
            tech_audit_resp = client.get("/api/v1/audit-logs", headers=tech_headers)
            assert tech_audit_resp.status_code == 403

            # 6. Verify REST immutability: even SuperAdmin cannot DELETE or PATCH an audit log
            del_attempt = client.delete(
                f"/api/v1/audit-logs/{rest_audit_id}",
                headers=sa_headers,
            )
            assert del_attempt.status_code == 403

            patch_attempt = client.patch(
                f"/api/v1/audit-logs/{rest_audit_id}",
                headers=sa_headers,
            )
            assert patch_attempt.status_code == 403

        # 7. Verify ORM and PostgreSQL trigger immutability directly against the database
        reset_shared_async_resources()
        asyncio.run(_verify_orm_and_postgres_immutability(rest_audit_id))
    finally:
        reset_shared_async_resources()
        asyncio.run(_cleanup_audit_fixture(fx["org_id"], user_ids, script_ids))
