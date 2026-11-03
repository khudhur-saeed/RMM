from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import compute_task_digest, sign_task_dispatch
from app.core.rbac import (
    Permission,
    Principal,
    ensure_agent_access,
    require_permissions,
)
from app.core.security import verify_agent_api_key
from app.core.ws_manager import ws_manager
from app.db.session import get_db
from app.models.agent import Agent
from app.models.site import Site
from app.models.software import InstalledSoftware
from app.schemas.agent import AgentHeartbeat, AgentRead
from app.schemas.software import SoftwareRead
from app.schemas.task import TaskDispatchFrame

router = APIRouter()


@router.get(
    "",
    response_model=List[AgentRead],
    status_code=status.HTTP_200_OK,
    summary="List all registered agents across sites",
)
async def list_agents(
    principal: Principal = Depends(require_permissions(Permission.AGENT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves monitored endpoints registered in the system,
    automatically scoped to the caller's site or organization boundaries.
    """
    stmt = select(Agent).order_by(Agent.created_at.desc())

    if principal.site_id is not None:
        stmt = stmt.where(Agent.site_id == principal.site_id)
    elif principal.org_id is not None:
        stmt = stmt.join(Site, Agent.site_id == Site.id).where(
            Site.org_id == principal.org_id
        )

    result = await db.execute(stmt)
    return result.scalars().all()


@router.get(
    "/{agent_id}",
    response_model=AgentRead,
    status_code=status.HTTP_200_OK,
    summary="Get single agent metadata by UUID",
)
async def get_agent(
    agent_id: UUID,
    principal: Principal = Depends(require_permissions(Permission.AGENT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves metadata for a specific agent node within the caller's RBAC scope."""
    agent = await ensure_agent_access(principal, agent_id, db)
    return agent


@router.get(
    "/{agent_id}/software",
    response_model=List[SoftwareRead],
    status_code=status.HTTP_200_OK,
    summary="List and search installed software packages for an agent",
)
async def get_agent_software(
    agent_id: UUID,
    search: Optional[str] = Query(
        default=None,
        description="Case-insensitive filter matching package name, publisher, or version",
    ),
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_permissions(Permission.AGENT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves the synchronized software inventory for a monitored endpoint,
    enforcing site-level RBAC access and supporting substring search.
    """
    await ensure_agent_access(principal, agent_id, db)

    stmt = select(InstalledSoftware).where(InstalledSoftware.agent_id == agent_id)

    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                InstalledSoftware.name.ilike(pattern),
                InstalledSoftware.publisher.ilike(pattern),
                InstalledSoftware.version.ilike(pattern),
            )
        )

    stmt = stmt.order_by(InstalledSoftware.name.asc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get(
    "/{agent_id}/telemetry",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get latest cached hardware, network, and heartbeat telemetry for an agent",
)
async def get_agent_telemetry(
    agent_id: UUID,
    principal: Principal = Depends(require_permissions(Permission.AGENT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves the latest telemetry snapshots cached in Redis for a monitored endpoint."""
    await ensure_agent_access(principal, agent_id, db)
    return await ws_manager.get_telemetry(agent_id)


@router.post(
    "/{agent_id}/tasks",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Dispatch an asynchronous shell command task to a connected agent",
)
async def dispatch_agent_task(
    request: Request,
    agent_id: UUID,
    command: str,
    timeout_sec: int = 30,
    principal: Principal = Depends(require_permissions(Permission.AGENT_DISPATCH)),
    db: AsyncSession = Depends(get_db),
):
    """
    Routes a signed TaskDispatchFrame over the active agent WebSocket tunnel.
    Requires `agents:dispatch` permission (SuperAdmin or SiteTechnician) and site access.
    """
    request.state.audit_target_agent_id = agent_id
    request.state.audit_command_text = command

    await ensure_agent_access(
        principal,
        agent_id,
        db,
        allow_unregistered_for_unscoped=True,
    )

    task_id = uuid4()
    request.state.audit_task_id = task_id
    payload_sha256 = compute_task_digest(
        task_id=task_id,
        command=command,
        timeout_sec=timeout_sec,
    )
    signature = sign_task_dispatch(
        task_id=task_id,
        command=command,
        timeout_sec=timeout_sec,
    )
    task_frame = TaskDispatchFrame(
        task_id=task_id,
        command=command,
        timeout_sec=timeout_sec,
        payload_sha256=payload_sha256,
        signature=signature,
    )
    ws_manager.register_dispatched_task(
        task_id=task_id,
        agent_id=agent_id,
        command_text=command,
        principal=principal,
    )
    routed = await ws_manager.route_to_agent(
        agent_id,
        task_frame.model_dump_json(),
        principal=principal,
    )
    if not routed:
        ws_manager.finalize_task_output(task_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Target agent is not currently connected to the C2 tunnel.",
        )
    return {
        "task_id": task_frame.task_id,
        "payload_sha256": payload_sha256,
        "signature": signature,
        "status": "dispatched",
    }


@router.post(
    "/{agent_id}/heartbeat",
    response_model=AgentRead,
    status_code=status.HTTP_200_OK,
    summary="Process authenticated agent heartbeat and update telemetry",
)
async def process_heartbeat(
    payload: AgentHeartbeat,
    request: Request,
    agent: Agent = Depends(verify_agent_api_key),
    db: AsyncSession = Depends(get_db),
):
    """
    Updates the agent's last_seen timestamp, public IP,
    and private IP upon receiving authenticated keep-alive telemetry.
    """
    agent.last_seen = datetime.now(timezone.utc)
    if request.client:
        agent.public_ip = request.client.host
    if payload.private_ip:
        agent.private_ip = payload.private_ip

    await db.commit()
    await db.refresh(agent)
    return agent
