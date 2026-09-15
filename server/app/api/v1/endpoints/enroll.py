from datetime import datetime, timezone
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.agent import Agent
from app.models.token import EnrollmentToken
from app.schemas.agent import AgentEnroll, AgentEnrollResponse

router = APIRouter()

@router.post(
    "",
    response_model=AgentEnrollResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll endpoint agent with one-time token verification",
)
async def enroll_agent(
    payload: AgentEnroll,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Executes atomic single-use enrollment verification:
    1. Locks token row (Pessimistic Lock) to prevent race conditions.
    2. Validates consumption flag and expiration window.
    3. Burns token immediately (is_used = True).
    4. Issues high-entropy Agent API Key and stores SHA-256 digest.
    5. Returns agent UUID and raw API key exactly once.
    """
    # 1. Pessimistic Row Lock & Token Retrieval
    token_stmt = (
        select(EnrollmentToken)
        .where(EnrollmentToken.token == payload.token)
        .with_for_update()
    )
    token_result = await db.execute(token_stmt)
    token_record = token_result.scalar_one_or_none()

    if not token_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enrollment token.",
        )

    # 2. Verify Single-Use Consumption Flag
    if token_record.is_used:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enrollment token has already been consumed.",
        )

    # 3. Verify Expiration Window
    current_time = datetime.now(timezone.utc)
    if current_time > token_record.expires_at:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token has expired.",
        )

    # 4. Burn-After-Use: Mark token as consumed
    token_record.is_used = True

    # 5. Generate Cryptographic Agent API Key and Hash Digest
    raw_api_key = f"rmm_sec_{secrets.token_urlsafe(36)}"
    api_key_hash = hashlib.sha256(raw_api_key.encode("utf-8")).hexdigest()

    # 6. Resolve Public IP & Persist Agent Entity
    resolved_ip = request.client.host if request.client else None

    new_agent = Agent(
        hostname=payload.hostname,
        os=payload.os,
        private_ip=payload.private_ip,
        public_ip=resolved_ip,
        site_id=token_record.site_id,
        api_key_hash=api_key_hash,
        last_seen=current_time,
    )

    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)

    # 7. Construct and Return AgentEnrollResponse with raw API key
    return AgentEnrollResponse(
        id=new_agent.id,
        site_id=new_agent.site_id,
        hostname=new_agent.hostname,
        os=new_agent.os,
        private_ip=new_agent.private_ip,
        public_ip=new_agent.public_ip,
        last_seen=new_agent.last_seen,
        created_at=new_agent.created_at,
        api_key=raw_api_key,
    )