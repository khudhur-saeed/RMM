from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import Permission, Principal, Role, require_permissions
from app.db.session import get_db
from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogRead

router = APIRouter()


@router.get(
    "",
    response_model=List[AuditLogRead],
    status_code=status.HTTP_200_OK,
    summary="List immutable security audit logs with multi-tenant isolation and optional filtering",
)
async def list_audit_logs(
    admin_id: Optional[UUID] = Query(
        default=None,
        description="Filter by executing operator/admin UUID",
    ),
    org_id: Optional[UUID] = Query(
        default=None,
        description="Filter by tenant organization UUID",
    ),
    site_id: Optional[UUID] = Query(
        default=None,
        description="Filter by site UUID",
    ),
    target_agent_id: Optional[UUID] = Query(
        default=None,
        description="Filter by target endpoint agent UUID",
    ),
    agent_id: Optional[UUID] = Query(
        default=None,
        description="Alias filter for target_agent_id",
    ),
    action: Optional[str] = Query(
        default=None,
        description="Filter by exact audit action identifier",
    ),
    search: Optional[str] = Query(
        default=None,
        description="Case-insensitive substring search across command_text, action, and admin_username",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    principal: Principal = Depends(require_permissions(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves immutable security audit logs ordered from newest to oldest.
    Restricted to roles holding `audit:read` (SuperAdmin and Auditor) and strictly
    scoped to the caller's organization/site boundaries when tenant-bound.
    """
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc())

    # Enforce strict multi-tenant isolation for organization/site-scoped principals
    if principal.role != Role.SUPER_ADMIN:
        if principal.site_id is not None:
            if site_id is not None and site_id != principal.site_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: requested site_id is outside caller's tenant boundary.",
                )
            stmt = stmt.where(AuditLog.site_id == principal.site_id)
        elif principal.org_id is not None:
            if org_id is not None and org_id != principal.org_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: requested org_id is outside caller's tenant boundary.",
                )
            stmt = stmt.where(AuditLog.org_id == principal.org_id)

    if org_id is not None:
        stmt = stmt.where(AuditLog.org_id == org_id)
    if site_id is not None:
        stmt = stmt.where(AuditLog.site_id == site_id)

    resolved_agent_filter = target_agent_id or agent_id
    if admin_id is not None:
        stmt = stmt.where(AuditLog.admin_id == admin_id)
    if resolved_agent_filter is not None:
        stmt = stmt.where(AuditLog.target_agent_id == resolved_agent_filter)
    if action and action.strip():
        stmt = stmt.where(AuditLog.action == action.strip())
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                AuditLog.command_text.ilike(pattern),
                AuditLog.action.ilike(pattern),
                AuditLog.admin_username.ilike(pattern),
            )
        )

    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get(
    "/{log_id}",
    response_model=AuditLogRead,
    status_code=status.HTTP_200_OK,
    summary="Get a single immutable audit log entry by UUID",
)
async def get_audit_log(
    log_id: UUID,
    principal: Principal = Depends(require_permissions(Permission.AUDIT_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves a specific immutable audit log record by ID within the caller's tenant boundary."""
    stmt = select(AuditLog).where(AuditLog.id == log_id)
    entry = (await db.execute(stmt)).scalar_one_or_none()
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log entry not found.",
        )

    if principal.role != Role.SUPER_ADMIN:
        if principal.site_id is not None and entry.site_id != principal.site_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: audit log belongs to another site.",
            )
        if principal.org_id is not None and entry.org_id != principal.org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: audit log belongs to another organization.",
            )

    return entry


@router.put("/{log_id}", status_code=status.HTTP_403_FORBIDDEN, include_in_schema=False)
@router.patch("/{log_id}", status_code=status.HTTP_403_FORBIDDEN, include_in_schema=False)
@router.delete("/{log_id}", status_code=status.HTTP_403_FORBIDDEN, include_in_schema=False)
async def reject_audit_log_mutation(
    log_id: UUID,
    _principal: Principal = Depends(require_permissions(Permission.AUDIT_READ)),
):
    """Explicitly blocks any attempt to update or delete an immutable audit log entry."""
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Audit log '{log_id}' is append-only and immutable; modification and deletion are strictly prohibited.",
    )
