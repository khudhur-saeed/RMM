from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
    db: AsyncSession = Depends(get_db),
):
    """
    Creates a root tenant organization.
    Enforces business uniqueness on the organization name.
    """
    # 1. Uniqueness check against PostgreSQL
    query = select(Organization).where(Organization.name == payload.name)
    result = await db.execute(query)
    existing_org = result.scalar_one_or_none()

    if existing_org:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Organization with name '{payload.name}' already exists.",
        )

    # 2. Instantiate and persist new ORM entity
    new_org = Organization(name=payload.name)
    db.add(new_org)
    await db.commit()
    await db.refresh(new_org)

    return new_org


@router.get(
    "",
    response_model=List[OrganizationRead],
    status_code=status.HTTP_200_OK,
    summary="List all tenant organizations",
)
async def list_organizations(
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves all tenant organizations registered within the platform.
    """
    query = select(Organization).order_by(Organization.created_at.desc())
    result = await db.execute(query)
    organizations = result.scalars().all()
    return organizations