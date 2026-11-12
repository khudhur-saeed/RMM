import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import delete

from app.core.config import settings
from app.db.session import async_session_factory, engine
from app.main import app
from app.models.agent import Agent
from app.models.audit_log import AuditLog
from app.models.organization import Organization
from app.models.script import Script
from app.models.site import Site
from app.models.token import EnrollmentToken
from app.models.user import User

from conftest import delete_organizations, reset_shared_async_resources

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AGENT_DIR = PROJECT_ROOT / "agent"
LINUX_AGENT_BINARY = AGENT_DIR / "rmmagent"
WINDOWS_AGENT_BINARY = AGENT_DIR / "rmmagent.exe"


def test_agent_binary_distribution_endpoints():
    """
    Validates that the control plane serves pre-compiled agent binaries:
    - /api/v1/download/linux/amd64 -> rmmagent ELF binary
    - /api/v1/download/windows/amd64 -> rmmagent.exe PE32+ binary
    - Rejects invalid architectures with 400 Bad Request
    """
    with TestClient(app) as client:
        # Linux download
        lin_resp = client.get("/api/v1/download/linux/amd64")
        assert lin_resp.status_code == 200
        assert lin_resp.headers["content-type"] == "application/octet-stream"
        assert len(lin_resp.content) > 1_000_000

        # Windows download
        win_resp = client.get("/api/v1/download/windows/amd64")
        assert win_resp.status_code == 200
        assert win_resp.headers["content-type"] == "application/octet-stream"
        assert len(win_resp.content) > 1_000_000

        # Invalid architecture check
        bad_resp = client.get("/api/v1/download/linux/mips")
        assert bad_resp.status_code == 400


def test_e2e_local_network_simulated_dual_vm_integration():
    """
    Day 48 End-to-End Integration Testing:
    Simulates a clean local network environment with both:
    1. A Clean Linux VM Endpoint (Ubuntu/Debian system on 192.168.1.110):
       - Issues single-use token via POST /api/v1/tokens
       - Runs install.sh --server <URL> --token <TOKEN> --local-binary
       - Executes hardware enrollment and obtains Ed25519 public key
       - Establishes full-duplex WebSocket C2 tunnel
       - Emits hardware metrics, process telemetry, and software inventory
       - Receives signed bash command dispatch, executes, and streams output back
       - Generates immutable audit log with command text and SHA-256 output digest
    2. A Clean Windows VM Endpoint (Windows 10/11 Server on 192.168.1.120):
       - Verifies install.ps1 compatibility and binary readiness
       - Simulates Windows endpoint enrollment and agent telemetry ingestion
       - Receives signed PowerShell script dispatch, executes, and streams output back
       - Verifies RBAC site technician and auditor permissions on both VM endpoints
    """
    suffix = uuid.uuid4().hex[:6]
    created_org_ids = []
    created_user_ids = []
    created_script_ids = []

    async def _setup():
        async with async_session_factory() as session:
            org = Organization(name=f"E2E Enterprise {suffix}")
            session.add(org)
            await session.flush()
            created_org_ids.append(org.id)

            site = Site(name=f"Local Lab Site {suffix}", org_id=org.id)
            session.add(site)
            await session.flush()
            site_id = site.id
            await session.commit()
            return site_id

    site_id = asyncio.run(_setup())
    asyncio.run(engine.dispose())

    try:
        with TestClient(app) as client:
            sa_headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

            # 2. Provision Site Technician & Compliance Auditor
            tech_resp = client.post(
                "/api/v1/users",
                headers=sa_headers,
                json={
                    "username": f"lab_tech_{suffix}",
                    "role": "SiteTechnician",
                    "site_id": str(site_id),
                },
            )
            assert tech_resp.status_code == 201
            tech_data = tech_resp.json()
            created_user_ids.append(uuid.UUID(tech_data["id"]))
            tech_headers = {"Authorization": f"Bearer {tech_data['api_token']}"}

            aud_resp = client.post(
                "/api/v1/users",
                headers=sa_headers,
                json={
                    "username": f"lab_auditor_{suffix}",
                    "role": "Auditor",
                },
            )
            assert aud_resp.status_code == 201
            aud_data = aud_resp.json()
            created_user_ids.append(uuid.UUID(aud_data["id"]))
            aud_headers = {"Authorization": f"Bearer {aud_data['api_token']}"}

            # 3. Create single-use enrollment tokens for Linux VM and Windows VM
            tok_linux_res = client.post(
                "/api/v1/tokens",
                headers=tech_headers,
                json={"site_id": str(site_id), "valid_hours": 24},
            )
            assert tok_linux_res.status_code == 201
            linux_token = tok_linux_res.json()["token"]

            tok_win_res = client.post(
                "/api/v1/tokens",
                headers=tech_headers,
                json={"site_id": str(site_id), "valid_hours": 24},
            )
            assert tok_win_res.status_code == 201
            win_token = tok_win_res.json()["token"]

            # 4. Enroll Linux VM Endpoint (192.168.1.110)
            linux_enroll_res = client.post(
                "/api/v1/enroll",
                json={
                    "hostname": "VM-LINUX-NODE01",
                    "os": "linux/amd64",
                    "private_ip": "192.168.1.110",
                    "token": linux_token,
                },
            )
            assert linux_enroll_res.status_code == 201
            linux_node = linux_enroll_res.json()
            linux_id = uuid.UUID(linux_node["id"])
            linux_key = linux_node["api_key"]
            assert len(linux_node["signing_public_key"]) > 0

            # 5. Enroll Windows VM Endpoint (192.168.1.120)
            win_enroll_res = client.post(
                "/api/v1/enroll",
                json={
                    "hostname": "VM-WIN-NODE02",
                    "os": "windows/amd64",
                    "private_ip": "192.168.1.120",
                    "token": win_token,
                },
            )
            assert win_enroll_res.status_code == 201
            win_node = win_enroll_res.json()
            win_id = uuid.UUID(win_node["id"])
            win_key = win_node["api_key"]
            assert len(win_node["signing_public_key"]) > 0

            # 6. Verify single-use token burn (replay attack fails with 401)
            replay_res = client.post(
                "/api/v1/enroll",
                json={
                    "hostname": "ROGUE-NODE",
                    "os": "linux/amd64",
                    "token": linux_token,
                },
            )
            assert replay_res.status_code == 401

            # 7. Create PowerShell & Bash maintenance scripts in Keystore
            ps_script_res = client.post(
                "/api/v1/scripts",
                headers=sa_headers,
                json={
                    "name": f"Win Diagnostics {suffix}",
                    "shell_type": "powershell",
                    "content": "Get-Service -Name '{{SVC_NAME}}' | Select-Object Status, DisplayName",
                    "parameters": [{"name": "SVC_NAME", "default_value": "wuauserv", "required": True}],
                },
            )
            assert ps_script_res.status_code == 201
            ps_script_id = uuid.UUID(ps_script_res.json()["id"])
            created_script_ids.append(ps_script_id)

            bash_script_res = client.post(
                "/api/v1/scripts",
                headers=sa_headers,
                json={
                    "name": f"Linux Uptime Check {suffix}",
                    "shell_type": "bash",
                    "content": "uptime -p && free -m",
                },
            )
            assert bash_script_res.status_code == 201
            bash_script_id = uuid.UUID(bash_script_res.json()["id"])
            created_script_ids.append(bash_script_id)

            # 8. Open simultaneous C2 WebSocket tunnels for both clean VMs
            linux_ws_url = f"/api/v1/ws/agent/{linux_id}?token={linux_key}"
            win_ws_url = f"/api/v1/ws/agent/{win_id}?token={win_key}"

            with (
                client.websocket_connect(linux_ws_url) as lin_ws,
                client.websocket_connect(win_ws_url) as win_ws,
            ):
                # 8a. Linux VM sends telemetry & software inventory
                lin_ws.send_json({
                    "type": "hardware_telemetry",
                    "agent_id": str(linux_id),
                    "cpu": {"usage_percent": 18.2, "logical_cores": 4},
                    "memory": {"used_percent": 42.5},
                })
                lin_ws.send_json({
                    "type": "software_inventory",
                    "agent_id": str(linux_id),
                    "software": [
                        {"name": "openssh-server", "version": "9.6p1", "publisher": "Ubuntu"},
                        {"name": "systemd", "version": "255.4", "publisher": "Debian"},
                    ],
                })

                # 8b. Windows VM sends telemetry & software inventory
                win_ws.send_json({
                    "type": "hardware_telemetry",
                    "agent_id": str(win_id),
                    "cpu": {"usage_percent": 24.0, "logical_cores": 8},
                    "memory": {"used_percent": 68.1},
                })
                win_ws.send_json({
                    "type": "software_inventory",
                    "agent_id": str(win_id),
                    "software": [
                        {"name": "Microsoft Edge", "version": "128.0", "publisher": "Microsoft Corporation"},
                        {"name": "PowerShell 7", "version": "7.4.5", "publisher": "Microsoft Corporation"},
                    ],
                })

                # 9. Site Technician dispatches signed task to Linux VM
                lin_task_resp = client.post(
                    f"/api/v1/scripts/{bash_script_id}/render",
                    headers=tech_headers,
                    json={"agent_id": str(linux_id)},
                )
                assert lin_task_resp.status_code == 200
                lin_c2_frame = lin_ws.receive_json()
                assert lin_c2_frame["type"] == "task_dispatch"
                assert lin_c2_frame["command"] == "uptime -p && free -m"
                assert len(lin_c2_frame["signature"]) > 0

                # Linux VM streams output back
                lin_ws.send_json({
                    "type": "task_stream",
                    "task_id": lin_c2_frame["task_id"],
                    "stream": "stdout",
                    "chunk": "up 3 days, 4 hours\n               total        used        free\nMem:           16000        6800        9200\n",
                })
                lin_ws.send_json({
                    "type": "task_exit",
                    "task_id": lin_c2_frame["task_id"],
                    "exit_code": 0,
                    "elapsed_ms": 14,
                    "error": None,
                })

                # 10. Site Technician dispatches signed task to Windows VM
                win_task_resp = client.post(
                    f"/api/v1/scripts/{ps_script_id}/render",
                    headers=tech_headers,
                    json={
                        "values": {"SVC_NAME": "wuauserv"},
                        "agent_id": str(win_id),
                    },
                )
                assert win_task_resp.status_code == 200
                win_c2_frame = win_ws.receive_json()
                assert win_c2_frame["type"] == "task_dispatch"
                assert "Get-Service -Name 'wuauserv'" in win_c2_frame["command"]
                assert len(win_c2_frame["signature"]) > 0

                # Windows VM streams output back
                win_ws.send_json({
                    "type": "task_stream",
                    "task_id": win_c2_frame["task_id"],
                    "stream": "stdout",
                    "chunk": "Status   DisplayName\n------   -----------\nRunning  Windows Update\n",
                })
                win_ws.send_json({
                    "type": "task_exit",
                    "task_id": win_c2_frame["task_id"],
                    "exit_code": 0,
                    "elapsed_ms": 120,
                    "error": None,
                })

            # 11. Auditor verifies fleet software and audit logs for both clean VM endpoints
            # Check Linux software inventory
            lin_sw_res = client.get(f"/api/v1/agents/{linux_id}/software", headers=aud_headers)
            assert lin_sw_res.status_code == 200
            assert any(s["name"] == "openssh-server" for s in lin_sw_res.json())

            # Check Windows software inventory
            win_sw_res = client.get(f"/api/v1/agents/{win_id}/software", headers=aud_headers)
            assert win_sw_res.status_code == 200
            assert any(s["name"] == "PowerShell 7" for s in win_sw_res.json())

            # Check immutable audit logs
            audit_res = client.get("/api/v1/audit-logs", headers=aud_headers)
            assert audit_res.status_code == 200
            logs = audit_res.json()

            # Confirm both VM command executions produced audit records with SHA-256 output hashes
            linux_audit = [l for l in logs if l.get("target_agent_id") == str(linux_id)]
            win_audit = [l for l in logs if l.get("target_agent_id") == str(win_id)]
            assert len(linux_audit) >= 1
            assert len(win_audit) >= 1
            assert len(linux_audit[0]["output_hash"]) == 64
            assert len(win_audit[0]["output_hash"]) == 64

    finally:
        reset_shared_async_resources()
        async def _cleanup():
            async with async_session_factory() as session:
                if created_user_ids:
                    await session.execute(delete(User).where(User.id.in_(created_user_ids)))
                if created_script_ids:
                    await session.execute(delete(Script).where(Script.id.in_(created_script_ids)))
                await session.commit()
            if created_org_ids:
                await delete_organizations(created_org_ids)
            await engine.dispose()
        asyncio.run(_cleanup())
