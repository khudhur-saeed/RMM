from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_agent_api_key, verify_operator_token
from app.core.ws_manager import ws_manager
from app.db.session import get_db
from app.models.agent import Agent
from app.models.software import InstalledSoftware
from app.schemas.agent import AgentHeartbeat, AgentRead
from app.schemas.software import SoftwareRead
from app.schemas.task import TaskDispatchFrame

router = APIRouter()


@router.get(
    "",
    response_model=List[AgentRead],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_operator_token)],
    summary="List all registered agents across sites",
)
async def list_agents(
    db: AsyncSession = Depends(get_db),
):
    """Retrieves all monitored endpoints registered in the system."""
    stmt = select(Agent).order_by(Agent.created_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get(
    "/{agent_id}",
    response_model=AgentRead,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_operator_token)],
    summary="Get single agent metadata by UUID",
)
async def get_agent(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Retrieves metadata for a specific agent node."""
    stmt = select(Agent).where(Agent.id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found.",
        )
    return agent


@router.get(
    "/{agent_id}/software",
    response_model=List[SoftwareRead],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_operator_token)],
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
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves the synchronized software inventory for a monitored endpoint,
    supporting real-time substring search across name, publisher, and version.
    """
    agent_stmt = select(Agent.id).where(Agent.id == agent_id)
    agent_exists = (await db.execute(agent_stmt)).scalar_one_or_none()
    if not agent_exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found.",
        )

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
    dependencies=[Depends(verify_operator_token)],
    summary="Get latest cached hardware, network, and heartbeat telemetry for an agent",
)
async def get_agent_telemetry(
    agent_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Retrieves the latest telemetry snapshots cached in Redis for a monitored endpoint."""
    stmt = select(Agent).where(Agent.id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found.",
        )

    return await ws_manager.get_telemetry(agent_id)


@router.post(
    "/{agent_id}/tasks",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_operator_token)],
    summary="Dispatch an asynchronous shell command task to a connected agent",
)
async def dispatch_agent_task(
    agent_id: UUID,
    command: str,
    timeout_sec: int = 30,
):
    """Routes a TaskDispatchFrame over the active agent WebSocket tunnel."""
    task_frame = TaskDispatchFrame(
        task_id=uuid4(),
        command=command,
        timeout_sec=timeout_sec,
    )
    routed = await ws_manager.route_to_agent(agent_id, task_frame.model_dump_json())
    if not routed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Target agent is not currently connected to the C2 tunnel.",
        )
    return {"task_id": task_frame.task_id, "status": "dispatched"}


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