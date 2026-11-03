from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import (
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
    Permission,
    Principal,
    Role,
    generate_user_api_token,
    get_current_principal,
    require_permissions,
)
from app.db.session import get_db
from app.models.organization import Organization
from app.models.site import Site
from app.models.user import User
from app.schemas.user import (
    PrincipalRead,
    RoleMetadataRead,
    UserCreate,
    UserCreateResponse,
    UserRead,
    UserUpdate,
)

router = APIRouter()


def _serialize_user(user: User, api_token: Optional[str] = None) -> UserRead | UserCreateResponse:
    perms = sorted(list(user.permissions), key=lambda p: p.value)
    base_data = {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": Role(user.role),
        "org_id": user.org_id,
        "site_id": user.site_id,
        "is_active": user.is_active,
        "permissions": perms,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }
    if api_token is not None:
        return UserCreateResponse(**base_data, api_token=api_token)
    return UserRead(**base_data)


@router.get(
    "/me",
    response_model=PrincipalRead,
    status_code=status.HTTP_200_OK,
    summary="Inspect the currently authenticated operator's RBAC identity and permissions",
)
async def get_current_operator_profile(
    principal: Principal = Depends(get_current_principal),
):
    """Returns the caller's resolved RBAC role, permission set, and tenant/site scope."""
    return PrincipalRead(
        id=principal.id,
        username=principal.username,
        role=principal.role,
        permissions=sorted(list(principal.permissions), key=lambda p: p.value),
        org_id=principal.org_id,
        site_id=principal.site_id,
        is_active=principal.is_active,
        is_bootstrap=principal.is_bootstrap,
    )


@router.get(
    "/roles",
    response_model=List[RoleMetadataRead],
    status_code=status.HTTP_200_OK,
    summary="List all RBAC roles (SuperAdmin, SiteTechnician, Auditor) and their permissions",
)
async def list_rbac_roles(
    _principal: Principal = Depends(get_current_principal),
):
    """Returns the canonical RBAC role hierarchy and granted permission matrices."""
    return [
        RoleMetadataRead(
            role=role,
            description=ROLE_DESCRIPTIONS[role],
            permissions=sorted(list(ROLE_PERMISSIONS[role]), key=lambda p: p.value),
        )
        for role in (Role.SUPER_ADMIN, Role.SITE_TECHNICIAN, Role.AUDITOR)
    ]


@router.post(
    "",
    response_model=UserCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new RBAC operator user and issue a bearer API token",
)
async def create_user(
    payload: UserCreate,
    _principal: Principal = Depends(require_permissions(Permission.USER_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    """
    Creates an operator account with role SuperAdmin, SiteTechnician, or Auditor.
    Validates organization and site foreign keys and returns the raw API token once.
    """
    resolved_org_id = payload.org_id

    if payload.site_id is not None:
        site_stmt = select(Site).where(Site.id == payload.site_id)
        site = (await db.execute(site_stmt)).scalar_one_or_none()
        if not site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Site with ID '{payload.site_id}' not found.",
            )
        if resolved_org_id is not None and resolved_org_id != site.org_id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Provided site_id does not belong to the specified org_id.",
            )
        resolved_org_id = site.org_id
    elif resolved_org_id is not None:
        org_stmt = select(Organization).where(Organization.id == resolved_org_id)
        org = (await db.execute(org_stmt)).scalar_one_or_none()
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization with ID '{resolved_org_id}' not found.",
            )

    raw_token, token_hash = generate_user_api_token()

    user = User(
        username=payload.username,
        email=payload.email,
        role=payload.role.value,
        api_token_hash=token_hash,
        org_id=resolved_org_id,
        site_id=payload.site_id,
        is_active=payload.is_active,
    )
    db.add(user)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User with username '{payload.username}' or email already exists.",
        )

    await db.refresh(user)
    return _serialize_user(user, api_token=raw_token)


@router.get(
    "",
    response_model=List[UserRead],
    status_code=status.HTTP_200_OK,
    summary="List RBAC operator users with optional role, organization, or site filtering",
)
async def list_users(
    role: Optional[Role] = Query(default=None, description="Filter users by RBAC role"),
    org_id: Optional[UUID] = Query(default=None, description="Filter users by organization UUID"),
    site_id: Optional[UUID] = Query(default=None, description="Filter users by site UUID"),
    principal: Principal = Depends(require_permissions(Permission.USER_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves registered operator accounts, respecting caller organization/site scope."""
    stmt = select(User).order_by(User.created_at.desc())

    if principal.org_id is not None:
        stmt = stmt.where(User.org_id == principal.org_id)
    if principal.site_id is not None:
        stmt = stmt.where(User.site_id == principal.site_id)

    if role is not None:
        stmt = stmt.where(User.role == role.value)
    if org_id is not None:
        stmt = stmt.where(User.org_id == org_id)
    if site_id is not None:
        stmt = stmt.where(User.site_id == site_id)

    users = (await db.execute(stmt)).scalars().all()
    return [_serialize_user(u) for u in users]


@router.get(
    "/{user_id}",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Get a single RBAC operator user by UUID",
)
async def get_user(
    user_id: UUID,
    principal: Principal = Depends(require_permissions(Permission.USER_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves metadata and derived permissions for a specific RBAC user."""
    stmt = select(User).where(User.id == user_id)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    if principal.org_id is not None and user.org_id != principal.org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to user outside your organization scope.",
        )
    return _serialize_user(user)


@router.patch(
    "/{user_id}",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Update an RBAC operator user's role, scope, or active status",
)
@router.put(
    "/{user_id}",
    response_model=UserRead,
    status_code=status.HTTP_200_OK,
    summary="Update an RBAC operator user's role, scope, or active status",
)
async def update_user(
    user_id: UUID,
    payload: UserUpdate,
    _principal: Principal = Depends(require_permissions(Permission.USER_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    """Updates role assignment, site/organization scope, or active status for an operator."""
    stmt = select(User).where(User.id == user_id)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    update_data = payload.model_dump(exclude_unset=True)

    if "site_id" in update_data and update_data["site_id"] is not None:
        site_stmt = select(Site).where(Site.id == update_data["site_id"])
        site = (await db.execute(site_stmt)).scalar_one_or_none()
        if not site:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Site with ID '{update_data['site_id']}' not found.",
            )
        user.site_id = site.id
        user.org_id = site.org_id
    elif "site_id" in update_data and update_data["site_id"] is None:
        user.site_id = None

    if "org_id" in update_data and "site_id" not in update_data:
        if update_data["org_id"] is not None:
            org_stmt = select(Organization).where(Organization.id == update_data["org_id"])
            org = (await db.execute(org_stmt)).scalar_one_or_none()
            if not org:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Organization with ID '{update_data['org_id']}' not found.",
                )
        user.org_id = update_data["org_id"]

    if "role" in update_data and update_data["role"] is not None:
        role_val = update_data["role"]
        user.role = role_val.value if isinstance(role_val, Role) else str(role_val)

    if "email" in update_data:
        user.email = update_data["email"]

    if "is_active" in update_data and update_data["is_active"] is not None:
        user.is_active = update_data["is_active"]

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email address is already in use by another operator.",
        )

    await db.refresh(user)
    return _serialize_user(user)


@router.post(
    "/{user_id}/rotate-token",
    response_model=UserCreateResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate an RBAC operator's bearer API token",
)
async def rotate_user_token(
    user_id: UUID,
    _principal: Principal = Depends(require_permissions(Permission.USER_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    """Generates a fresh bearer token for the user and invalidates the previous token."""
    stmt = select(User).where(User.id == user_id)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    raw_token, token_hash = generate_user_api_token()
    user.api_token_hash = token_hash
    await db.commit()
    await db.refresh(user)
    return _serialize_user(user, api_token=raw_token)


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an RBAC operator user account",
)
async def delete_user(
    user_id: UUID,
    _principal: Principal = Depends(require_permissions(Permission.USER_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    """Permanently removes an operator user account from the system."""
    stmt = select(User).where(User.id == user_id)
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    await db.delete(user)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
