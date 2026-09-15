from datetime import datetime, timezone
from typing import List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.agent import Agent
from app.schemas.agent import AgentHeartbeat, AgentRead

router = APIRouter()


@router.get(
    "",
    response_model=List[AgentRead],
    status_code=status.HTTP_200_OK,
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


@router.post(
    "/{agent_id}/heartbeat",
    response_model=AgentRead,
    status_code=status.HTTP_200_OK,
    summary="Process agent heartbeat and update telemetry",
)
async def process_heartbeat(
    agent_id: UUID,
    payload: AgentHeartbeat,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Updates the agent's last_seen timestamp, public IP,
    and private IP upon receiving keep-alive telemetry.
    """
    stmt = select(Agent).where(Agent.id == agent_id)
    result = await db.execute(stmt)
    agent = result.scalar_one_or_none()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found.",
        )

    agent.last_seen = datetime.now(timezone.utc)
    if request.client:
        agent.public_ip = request.client.host
    if payload.private_ip:
        agent.private_ip = payload.private_ip

    await db.commit()
    await db.refresh(agent)
    return agent