from datetime import datetime, timedelta, timezone
import secrets
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_operator_token
from app.db.session import get_db
from app.models.site import Site
from app.models.token import EnrollmentToken
from app.schemas.token import EnrollmentTokenCreate, EnrollmentTokenPublic, EnrollmentTokenRead

router = APIRouter(dependencies=[Depends(verify_operator_token)])


@router.post(
    "",
    response_model=EnrollmentTokenRead,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a cryptographically secure enrollment token",
)
async def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Issues a time-limited, cryptographically random token scoped to a target site.
    Enforces foreign key validation on the parent site.
    """
    # 1. Foreign Key Verification: Ensure the target site exists
    site_query = select(Site).where(Site.id == payload.site_id)
    site_result = await db.execute(site_query)
    target_site = site_result.scalar_one_or_none()

    if not target_site:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target site with ID '{payload.site_id}' not found.",
        )

    # 2. Cryptographic generation & expiration calculation
    raw_token = secrets.token_urlsafe(32)
    expiration_timestamp = datetime.now(timezone.utc) + timedelta(hours=payload.valid_hours)

    # 3. Instantiate and persist the token entity
    new_token = EnrollmentToken(
        token=raw_token,
        site_id=payload.site_id,
        expires_at=expiration_timestamp,
    )
    db.add(new_token)
    await db.commit()
    await db.refresh(new_token)

    return new_token


@router.get(
    "",
    response_model=List[EnrollmentTokenPublic],
    status_code=status.HTTP_200_OK,
    summary="List enrollment tokens with optional site filtering",
)
async def list_enrollment_tokens(
    site_id: Optional[UUID] = Query(
        default=None,
        description="Filter tokens by site UUID",
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves all generated enrollment tokens, optionally filtered by site identifier.
    """
    query = select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc())

    if site_id:
        query = query.where(EnrollmentToken.site_id == site_id)

    result = await db.execute(query)
    tokens = result.scalars().all()
    return tokens