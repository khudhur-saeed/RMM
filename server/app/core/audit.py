import hashlib
import json
import logging
import re
from typing import Any, Dict, Optional, Union
from uuid import UUID

from fastapi import Request, Response
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.rbac import (
    BOOTSTRAP_SUPERADMIN_ID,
    Principal,
    extract_bearer_token,
    resolve_principal_from_token,
)
from app.db.session import async_session_factory
from app.models.agent import Agent
from app.models.audit_log import AuditLog
from app.models.site import Site

logger = logging.getLogger("rmm.audit")

_AGENT_PATH_RE = re.compile(
    r"^/api/v1/(?:agents|ws/operator)/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$)"
)
_HEARTBEAT_PATH_RE = re.compile(r"^/api/v1/agents/[0-9a-fA-F-]+/heartbeat/?$")
_DOWNLOAD_PATH_RE = re.compile(r"^/api/v1/download/(?:checksums/)?[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+/?$")
_SKIP_AUDIT_PREFIXES = (
    "/api/v1/health",
    "/api/v1/enroll",
    "/api/v1/download",
    "/api/v1/keys/public",
    "/api/v1/openapi.json",
    "/api/v1/docs",
    "/api/v1/redoc",
)


def compute_output_hash(output: Union[bytes, str, None]) -> str:
    """Computes the lowercase SHA-256 hex digest of command output or response payload."""
    if output is None:
        raw = b""
    elif isinstance(output, bytes):
        raw = output
    else:
        raw = str(output).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _try_parse_uuid(value: Any) -> Optional[UUID]:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value).strip())
    except (ValueError, TypeError, AttributeError):
        return None


async def record_audit_log(
    *,
    principal: Optional[Principal] = None,
    admin_id: Optional[UUID] = None,
    admin_username: Optional[str] = None,
    admin_role: Optional[str] = None,
    org_id: Optional[Union[UUID, str]] = None,
    site_id: Optional[Union[UUID, str]] = None,
    target_agent_id: Optional[Union[UUID, str]] = None,
    task_id: Optional[Union[UUID, str]] = None,
    action: str,
    method: str,
    path: str,
    command_text: str,
    output_hash: Optional[str] = None,
    output_content: Optional[Union[bytes, str]] = None,
    status_code: int = 200,
    client_ip: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> Optional[AuditLog]:
    """
    Appends an immutable security audit record into the PostgreSQL `audit_logs` table,
    automatically binding tenant `org_id` and `site_id` metadata.
    """
    try:
        resolved_admin_id = (
            admin_id
            or (principal.id if principal and principal.id else None)
            or BOOTSTRAP_SUPERADMIN_ID
        )
        resolved_username = (
            admin_username
            or (principal.username if principal else None)
            or "bootstrap-superadmin"
        )
        resolved_role = (
            admin_role
            or (principal.role.value if principal else None)
            or "SuperAdmin"
        )
        resolved_org_id = _try_parse_uuid(org_id) or (
            principal.org_id if principal else None
        )
        resolved_site_id = _try_parse_uuid(site_id) or (
            principal.site_id if principal else None
        )
        resolved_agent_id = _try_parse_uuid(target_agent_id)
        resolved_task_id = _try_parse_uuid(task_id)
        resolved_hash = output_hash or compute_output_hash(output_content)

        async with async_session_factory() as session:
            if resolved_agent_id is not None and (
                resolved_org_id is None or resolved_site_id is None
            ):
                stmt = (
                    select(Agent.site_id, Site.org_id)
                    .join(Site, Agent.site_id == Site.id)
                    .where(Agent.id == resolved_agent_id)
                )
                row = (await session.execute(stmt)).first()
                if row:
                    if resolved_site_id is None:
                        resolved_site_id = row[0]
                    if resolved_org_id is None:
                        resolved_org_id = row[1]

            entry = AuditLog(
                admin_id=resolved_admin_id,
                admin_username=resolved_username,
                admin_role=resolved_role,
                org_id=resolved_org_id,
                site_id=resolved_site_id,
                target_agent_id=resolved_agent_id,
                task_id=resolved_task_id,
                action=action[:128],
                method=method[:16],
                path=path[:255],
                command_text=command_text or "",
                output_hash=resolved_hash,
                status_code=status_code,
                client_ip=client_ip,
                details=details,
            )

            session.add(entry)
            await session.commit()
            await session.refresh(entry)
        return entry
    except Exception as exc:
        logger.warning("Failed to persist audit log entry for action [%s]: %s", action, exc)
        return None


def _extract_target_agent_from_request(
    path: str,
    query_params: Any,
    parsed_req_json: Optional[Dict[str, Any]],
) -> Optional[UUID]:
    match = _AGENT_PATH_RE.match(path)
    if match:
        return _try_parse_uuid(match.group(1))

    q_agent = query_params.get("agent_id") or query_params.get("target_agent_id")
    if q_agent:
        parsed = _try_parse_uuid(q_agent)
        if parsed:
            return parsed

    if isinstance(parsed_req_json, dict):
        for key in ("agent_id", "target_agent_id", "target_agent"):
            if key in parsed_req_json and parsed_req_json[key]:
                parsed = _try_parse_uuid(parsed_req_json[key])
                if parsed:
                    return parsed
    return None


def _extract_command_text_from_request(
    method: str,
    path: str,
    query_params: Any,
    parsed_req_json: Optional[Dict[str, Any]],
    raw_req_body: bytes,
    parsed_resp_json: Optional[Dict[str, Any]],
) -> str:
    # 1. If response contains rendered_command (e.g. POST /scripts/{id}/render), prefer it
    if isinstance(parsed_resp_json, dict) and parsed_resp_json.get("rendered_command"):
        return str(parsed_resp_json["rendered_command"])

    # 2. Query parameter ?command=... (e.g. POST /agents/{id}/tasks?command=...)
    q_cmd = query_params.get("command")
    if q_cmd:
        return str(q_cmd)

    # 3. Common command/payload fields in JSON request body
    if isinstance(parsed_req_json, dict):
        for key in ("command", "rendered_command", "content", "payload"):
            if key in parsed_req_json and parsed_req_json[key] is not None:
                return str(parsed_req_json[key])
        return json.dumps(parsed_req_json, sort_keys=True)

    if raw_req_body:
        try:
            return raw_req_body.decode("utf-8")[:4096]
        except UnicodeDecodeError:
            pass

    return f"{method} {path}"


class AuditLogMiddleware(BaseHTTPMiddleware):
    """
    ASGI Middleware that records an immutable audit log entry in PostgreSQL
    for all operator control-plane command dispatches and state-mutating REST actions.
    Captures:
    - `admin_id` (and `admin_username`, `admin_role`)
    - `target_agent_id`
    - `command_text`
    - `output_hash` (SHA-256 hex digest of the command/response output)
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method.upper()

        # Skip non-API routes, read-only GET/HEAD/OPTIONS probes, and agent-initiated heartbeats/enrollment
        if (
            method in ("GET", "HEAD", "OPTIONS")
            or not path.startswith("/api/v1")
            or any(path.startswith(prefix) for prefix in _SKIP_AUDIT_PREFIXES)
            or _HEARTBEAT_PATH_RE.match(path)
            or path.startswith("/api/v1/audit")
        ):
            return await call_next(request)

        # Cache incoming request body bytes before passing to route handler
        raw_req_body = await request.body()
        parsed_req_json: Optional[Dict[str, Any]] = None
        if raw_req_body:
            try:
                candidate = json.loads(raw_req_body)
                if isinstance(candidate, dict):
                    parsed_req_json = candidate
            except json.JSONDecodeError:
                parsed_req_json = None

        response = await call_next(request)

        # Resolve authenticated operator Principal
        principal: Optional[Principal] = getattr(request.state, "principal", None)
        if principal is None:
            raw_token = extract_bearer_token(
                request.headers.get("authorization"),
                request.headers.get("x-api-key"),
            )
            if raw_token:
                principal = await resolve_principal_from_token(raw_token)

        # Do not create operator audit log entries for unauthenticated (401) probes
        if principal is None:
            return response

        # Read response body stream to compute deterministic SHA-256 output_hash
        resp_chunks = [chunk async for chunk in response.body_iterator]
        resp_bytes = b"".join(resp_chunks)

        parsed_resp_json: Optional[Dict[str, Any]] = None
        if resp_bytes:
            try:
                resp_candidate = json.loads(resp_bytes)
                if isinstance(resp_candidate, dict):
                    parsed_resp_json = resp_candidate
            except json.JSONDecodeError:
                parsed_resp_json = None

        target_agent_id: Optional[UUID] = getattr(
            request.state, "audit_target_agent_id", None
        ) or _extract_target_agent_from_request(
            path, request.query_params, parsed_req_json
        )

        command_text: str = getattr(
            request.state, "audit_command_text", None
        ) or _extract_command_text_from_request(
            method,
            path,
            request.query_params,
            parsed_req_json,
            raw_req_body,
            parsed_resp_json,
        )

        task_id: Optional[UUID] = getattr(request.state, "audit_task_id", None)
        if task_id is None and isinstance(parsed_resp_json, dict):
            task_id = _try_parse_uuid(
                parsed_resp_json.get("task_id")
                or parsed_resp_json.get("dispatched_task_id")
            )

        output_hash: str = getattr(
            request.state, "audit_output_hash", None
        ) or compute_output_hash(resp_bytes)

        action: str = getattr(
            request.state, "audit_action", None
        ) or f"{method} {path}"

        client_ip = request.client.host if request.client else None

        audit_entry = await record_audit_log(
            principal=principal,
            target_agent_id=target_agent_id,
            task_id=task_id,
            action=action,
            method=method,
            path=path,
            command_text=command_text,
            output_hash=output_hash,
            status_code=response.status_code,
            client_ip=client_ip,
        )

        headers = dict(response.headers)
        headers["X-Audit-Output-Hash"] = output_hash
        if audit_entry is not None:
            headers["X-Audit-Log-Id"] = str(audit_entry.id)

        return Response(
            content=resp_bytes,
            status_code=response.status_code,
            headers=headers,
            media_type=response.media_type,
            background=response.background,
        )
