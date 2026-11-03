from datetime import datetime, timedelta, timezone
import secrets
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import (
    Permission,
    Principal,
    ensure_site_access,
    require_permissions,
)
from app.db.session import get_db
from app.models.site import Site
from app.models.token import EnrollmentToken
from app.schemas.token import (
    EnrollmentTokenCreate,
    EnrollmentTokenPublic,
    EnrollmentTokenRead,
)

router = APIRouter()


@router.post(
    "",
    response_model=EnrollmentTokenRead,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a cryptographically secure enrollment token",
)
async def create_enrollment_token(
    payload: EnrollmentTokenCreate,
    principal: Principal = Depends(require_permissions(Permission.TOKEN_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Issues a time-limited, cryptographically random token scoped to a target site.
    Enforces foreign key validation and site-level RBAC access (`tokens:write`).
    """
    await ensure_site_access(principal, payload.site_id, db)

    raw_token = secrets.token_urlsafe(32)
    expiration_timestamp = datetime.now(timezone.utc) + timedelta(
        hours=payload.valid_hours
    )

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
    principal: Principal = Depends(require_permissions(Permission.TOKEN_READ)),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves enrollment tokens visible to the caller's RBAC scope,
    optionally filtered by site identifier.
    """
    if site_id is not None:
        if not principal.can_access_site(site_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied: role '{principal.role.value}' is not authorized "
                    f"to inspect tokens for site '{site_id}'."
                ),
            )

    query = select(EnrollmentToken).order_by(EnrollmentToken.created_at.desc())

    if principal.site_id is not None:
        query = query.where(EnrollmentToken.site_id == principal.site_id)
    elif principal.org_id is not None:
        query = query.join(Site, EnrollmentToken.site_id == Site.id).where(
            Site.org_id == principal.org_id
        )

    if site_id:
        query = query.where(EnrollmentToken.site_id == site_id)

    result = await db.execute(query)
    tokens = result.scalars().all()
    return tokens
