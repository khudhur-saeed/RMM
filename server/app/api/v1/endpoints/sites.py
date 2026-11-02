from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import verify_operator_token
from app.db.session import get_db
from app.models.organization import Organization
from app.models.site import Site
from app.schemas.site import SiteCreate, SiteRead

router = APIRouter(dependencies=[Depends(verify_operator_token)])


@router.post(
    "",
    response_model=SiteRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new site under an organization",
)
async def create_site(
    payload: SiteCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Creates a physical or logical site linked to a tenant organization.
    Enforces foreign key existence and prevents duplicate site names within the same tenant.
    """
    # 1. Foreign Key Verification: Check if parent organization exists
    org_query = select(Organization).where(Organization.id == payload.org_id)
    org_result = await db.execute(org_query)
    parent_org = org_result.scalar_one_or_none()

    if not parent_org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Parent organization with ID '{payload.org_id}' not found.",
        )

    # 2. Scope-based uniqueness check: Prevent duplicate site names within the same organization
    site_query = select(Site).where(
        Site.org_id == payload.org_id,
        Site.name == payload.name,
    )
    site_result = await db.execute(site_query)
    existing_site = site_result.scalar_one_or_none()

    if existing_site:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with name '{payload.name}' already exists in this organization.",
        )

    # 3. Instantiate and persist new Site entity
    new_site = Site(
        name=payload.name,
        org_id=payload.org_id,
    )
    db.add(new_site)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Site with name '{payload.name}' already exists in this organization.",
        )
    await db.refresh(new_site)

    return new_site


@router.get(
    "",
    response_model=List[SiteRead],
    status_code=status.HTTP_200_OK,
    summary="List sites with optional organization filtering",
)
async def list_sites(
    org_id: Optional[UUID] = Query(
        default=None,
        description="Filter sites by parent organization UUID",
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves all sites, optionally scoped to a single organization.
    """
    query = select(Site).order_by(Site.created_at.desc())

    if org_id:
        query = query.where(Site.org_id == org_id)

    result = await db.execute(query)
    sites = result.scalars().all()
    return sites