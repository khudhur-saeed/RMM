from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.agent import Agent
from app.models.token import EnrollmentToken
from app.schemas.agent import AgentEnroll, AgentRead, AgentHeartbeat

router = APIRouter()


@router.post(
    "/enroll",
    response_model=AgentRead,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll a new agent using a scoped enrollment token",
)
async def enroll_agent(
    payload: AgentEnroll,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Validates an enrollment token, bounds the agent to the token's site,
    resolves client IP, and registers the agent into the fleet.
    """
    # 1. Cryptographic validation: Verify token existence
    token_query = select(EnrollmentToken).where(EnrollmentToken.token == payload.token)
    token_result = await db.execute(token_query)
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment token.",
        )

    # 2. Expiration Guard: Verify token is still within its validity window
    current_time = datetime.now(timezone.utc)
    if current_time > token_record.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token has expired.",
        )

    # 3. Resolve public network address from incoming request
    resolved_ip = request.client.host if request.client else None

    # 4. Instantiate new Agent entity bound to the token's parent site
    new_agent = Agent(
        hostname=payload.hostname,
        os=payload.os,
        private_ip=payload.private_ip,
        public_ip=resolved_ip,
        site_id=token_record.site_id,
        last_seen=current_time,
    )

    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)

    return new_agent


@router.get(
    "",
    response_model=List[AgentRead],
    status_code=status.HTTP_200_OK,
    summary="List agents with optional site filtering",
)
async def list_agents(
    site_id: Optional[UUID] = Query(
        default=None,
        description="Filter agents by target site UUID",
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves all enrolled agents, optionally filtered by site identifier.
    """
    query = select(Agent).order_by(Agent.created_at.desc())

    if site_id:
        query = query.where(Agent.site_id == site_id)

    result = await db.execute(query)
    agents = result.scalars().all()
    return agents

@router.post(
    "/{agent_id}/heartbeat",
    response_model=AgentRead,
    status_code=status.HTTP_200_OK,
    summary="Process periodic heartbeat and update agent telemetry",
)
async def agent_heartbeat(
    agent_id: UUID,
    payload: AgentHeartbeat,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Processes an incoming heartbeat from an active agent:
    Updates last_seen timestamp, public IP, and optionally updates private IP.
    """
    # 1. Verification: Ensure target agent exists
    query = select(Agent).where(Agent.id == agent_id)
    result = await db.execute(query)
    agent_record = result.scalar_one_or_none()

    if not agent_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent with ID '{agent_id}' not found.",
        )

    # 2. Extract network metadata and current UTC time
    current_time = datetime.now(timezone.utc)
    resolved_public_ip = request.client.host if request.client else None

    # 3. Apply state mutation
    agent_record.last_seen = current_time
    if resolved_public_ip:
        agent_record.public_ip = resolved_public_ip
    if payload.private_ip:
        agent_record.private_ip = payload.private_ip

    await db.commit()
    await db.refresh(agent_record)

    return agent_record