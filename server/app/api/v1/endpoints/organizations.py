from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import Permission, Principal, require_permissions
from app.db.session import get_db
from app.models.organization import Organization
from app.schemas.organization import OrganizationCreate, OrganizationRead

router = APIRouter()


@router.post(
    "",
    response_model=OrganizationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new tenant organization",
)
async def create_organization(
    payload: OrganizationCreate,
    _principal: Principal = Depends(require_permissions(Permission.ORG_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Creates a root tenant organization.
    Restricted to SuperAdmin (`organizations:write`).
    Enforces business uniqueness on the organization name.
    """
    query = select(Organization).where(Organization.name == payload.name)
    result = await db.execute(query)
    existing_org = result.scalar_one_or_none()

    if existing_org:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization with name '{payload.name}' already exists.",
        )

    new_org = Organization(name=payload.name)
    db.add(new_org)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization with name '{payload.name}' already exists.",
        )
    await db.refresh(new_org)

    return new_org


@router.get(
    "",
    response_model=List[OrganizationRead],
    status_code=status.HTTP_200_OK,
    summary="List all tenant organizations",
)
async def list_organizations(
    principal: Principal = Depends(require_permissions(Permission.ORG_READ)),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves tenant organizations registered within the platform.
    Scoped to `principal.org_id` when the caller is bound to a specific tenant.
    """
    query = select(Organization).order_by(Organization.created_at.desc())
    if principal.org_id is not None:
        query = query.where(Organization.id == principal.org_id)

    result = await db.execute(query)
    organizations = result.scalars().all()
    return organizations
