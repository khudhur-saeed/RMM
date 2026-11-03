from dataclasses import dataclass
import hashlib
import re
import secrets
from typing import Callable, FrozenSet, Optional, Sequence, Tuple, Union
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request, WebSocket, status
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.db.session import async_session_factory, get_db
from app.models.agent import Agent
from app.models.site import Site
from app.models.user import (
    ROLE_DESCRIPTIONS,
    ROLE_PERMISSIONS,
    Permission,
    Role,
    User,
)

# Deterministic UUIDs for bootstrap environment tokens
BOOTSTRAP_SUPERADMIN_ID = UUID("00000000-0000-0000-0000-000000000001")
BOOTSTRAP_TECHNICIAN_ID = UUID("00000000-0000-0000-0000-000000000002")
BOOTSTRAP_AUDITOR_ID = UUID("00000000-0000-0000-0000-000000000003")

# Public or Agent-authenticated endpoints that bypass operator RBAC middleware
_PUBLIC_EXACT_PATHS: FrozenSet[str] = frozenset(
    {
        "/api/v1/health",
        "/api/v1/enroll",
        "/api/v1/keys/public",
        "/api/v1/openapi.json",
        "/api/v1/docs",
        "/api/v1/redoc",
    }
)
_AGENT_HEARTBEAT_RE = re.compile(r"^/api/v1/agents/[0-9a-fA-F-]+/heartbeat/?$")


@dataclass(frozen=True)
class Principal:
    """
    Immutable security context representing an authenticated control-plane operator.
    Encapsulates RBAC role, derived permission set, and optional organization/site boundaries.
    """

    id: Optional[UUID]
    username: str
    role: Role
    org_id: Optional[UUID] = None
    site_id: Optional[UUID] = None
    is_active: bool = True
    is_bootstrap: bool = False

    @property
    def permissions(self) -> FrozenSet[Permission]:
        if not self.is_active:
            return frozenset()
        return ROLE_PERMISSIONS.get(self.role, frozenset())

    def has_permission(self, permission: Union[Permission, str]) -> bool:
        if not self.is_active:
            return False
        if self.role == Role.SUPER_ADMIN:
            return True
        perm = Permission(permission) if isinstance(permission, str) else permission
        return perm in self.permissions

    def has_any_role(self, *roles: Union[Role, str]) -> bool:
        if not self.is_active:
            return False
        normalized = {Role(r) if isinstance(r, str) else r for r in roles}
        return self.role in normalized

    def can_access_org(self, target_org_id: UUID) -> bool:
        """Verifies whether this principal can access resources under target_org_id."""
        if self.role == Role.SUPER_ADMIN:
            return True
        if self.org_id is not None and self.org_id != target_org_id:
            return False
        return True

    def can_access_site(
        self,
        target_site_id: UUID,
        target_org_id: Optional[UUID] = None,
    ) -> bool:
        """Verifies whether this principal can access resources under target_site_id."""
        if self.role == Role.SUPER_ADMIN:
            return True
        if self.site_id is not None and self.site_id != target_site_id:
            return False
        if (
            self.org_id is not None
            and target_org_id is not None
            and self.org_id != target_org_id
        ):
            return False
        return True


def extract_bearer_token(
    authorization: Optional[str],
    x_api_key: Optional[str] = None,
) -> Optional[str]:
    """Extracts a bearer token from Authorization header or X-API-Key header."""
    if authorization:
        scheme, _, param = authorization.partition(" ")
        if scheme.lower() == "bearer" and param.strip():
            return param.strip()
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    return None


def hash_api_token(raw_token: str) -> str:
    """Computes the lowercase SHA-256 hex digest of an operator bearer token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_user_api_token() -> Tuple[str, str]:
    """Generates a cryptographically random operator bearer token and its SHA-256 hash."""
    raw_token = f"rmm_usr_{secrets.token_urlsafe(36)}"
    return raw_token, hash_api_token(raw_token)


async def resolve_principal_from_token(
    raw_token: str,
    db: Optional[AsyncSession] = None,
) -> Optional[Principal]:
    """
    Resolves an operator bearer token into a typed RBAC Principal.
    Checks bootstrap environment tokens first (constant-time), then queries the `users` table.
    """
    if not raw_token:
        return None

    # 1. Bootstrap SuperAdmin token from settings
    if settings.ADMIN_API_TOKEN and secrets.compare_digest(
        raw_token, settings.ADMIN_API_TOKEN
    ):
        return Principal(
            id=BOOTSTRAP_SUPERADMIN_ID,
            username="bootstrap-superadmin",
            role=Role.SUPER_ADMIN,
            org_id=None,
            site_id=None,
            is_active=True,
            is_bootstrap=True,
        )

    # 2. Optional bootstrap SiteTechnician token from settings
    if settings.TECHNICIAN_API_TOKEN and secrets.compare_digest(
        raw_token, settings.TECHNICIAN_API_TOKEN
    ):
        return Principal(
            id=BOOTSTRAP_TECHNICIAN_ID,
            username="bootstrap-technician",
            role=Role.SITE_TECHNICIAN,
            org_id=None,
            site_id=None,
            is_active=True,
            is_bootstrap=True,
        )

    # 3. Optional bootstrap Auditor token from settings
    if settings.AUDITOR_API_TOKEN and secrets.compare_digest(
        raw_token, settings.AUDITOR_API_TOKEN
    ):
        return Principal(
            id=BOOTSTRAP_AUDITOR_ID,
            username="bootstrap-auditor",
            role=Role.AUDITOR,
            org_id=None,
            site_id=None,
            is_active=True,
            is_bootstrap=True,
        )

    # 4. Database lookup in `users` table via SHA-256 digest
    token_hash = hash_api_token(raw_token)
    stmt = select(User).where(User.api_token_hash == token_hash)

    if db is not None:
        user = (await db.execute(stmt)).scalar_one_or_none()
    else:
        async with async_session_factory() as session:
            user = (await session.execute(stmt)).scalar_one_or_none()

    if not user:
        return None

    return Principal(
        id=user.id,
        username=user.username,
        role=Role(user.role),
        org_id=user.org_id,
        site_id=user.site_id,
        is_active=user.is_active,
        is_bootstrap=False,
    )


async def get_current_principal(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    """
    FastAPI dependency that authenticates the caller and resolves their RBAC Principal.
    Reuses `request.state.principal` when pre-populated by RBACMiddleware.
    """
    pre_resolved: Optional[Principal] = getattr(request.state, "principal", None)
    if pre_resolved is not None:
        if not pre_resolved.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operator account is disabled.",
            )
        return pre_resolved

    candidate = extract_bearer_token(authorization, x_api_key)
    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing operator authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    principal = await resolve_principal_from_token(candidate, db=db)
    if not principal:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing operator authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not principal.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operator account is disabled.",
        )

    request.state.principal = principal
    return principal


def require_permissions(*required_permissions: Permission) -> Callable[..., Principal]:
    """
    FastAPI dependency factory that enforces one or more granular RBAC permissions.
    Raises HTTP 403 Forbidden if the authenticated principal lacks any required permission.
    """

    async def _check_permissions(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        missing = [
            perm.value
            for perm in required_permissions
            if not principal.has_permission(perm)
        ]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Permission denied: role '{principal.role.value}' lacks required "
                    f"permission(s): {', '.join(missing)}."
                ),
            )
        return principal

    return _check_permissions


def require_roles(*allowed_roles: Role) -> Callable[..., Principal]:
    """
    FastAPI dependency factory that restricts an endpoint to specific RBAC roles.
    Raises HTTP 403 Forbidden if the authenticated principal's role is not in `allowed_roles`.
    """

    async def _check_roles(
        principal: Principal = Depends(get_current_principal),
    ) -> Principal:
        if not principal.has_any_role(*allowed_roles):
            allowed_str = ", ".join(r.value for r in allowed_roles)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Access denied: role '{principal.role.value}' is not authorized. "
                    f"Required role(s): {allowed_str}."
                ),
            )
        return principal

    return _check_roles


def ensure_org_access(principal: Principal, target_org_id: UUID) -> None:
    """Raises HTTP 403 Forbidden if the principal is not allowed to access target_org_id."""
    if not principal.can_access_org(target_org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied: role '{principal.role.value}' is not authorized "
                f"to access organization '{target_org_id}'."
            ),
        )


async def ensure_site_access(
    principal: Principal,
    target_site_id: UUID,
    db: AsyncSession,
) -> Site:
    """
    Loads the target Site from PostgreSQL (raising 404 if missing) and verifies
    that the authenticated principal is permitted to operate on that site.
    """
    stmt = select(Site).where(Site.id == target_site_id)
    site = (await db.execute(stmt)).scalar_one_or_none()
    if not site:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target site with ID '{target_site_id}' not found.",
        )

    if not principal.can_access_site(site.id, site.org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied: role '{principal.role.value}' is scoped to site "
                f"'{principal.site_id}' and cannot access site '{target_site_id}'."
            ),
        )
    return site


async def ensure_agent_access(
    principal: Principal,
    agent_id: UUID,
    db: AsyncSession,
    allow_unregistered_for_unscoped: bool = False,
) -> Optional[Agent]:
    """
    Loads the target Agent (and its Site) from PostgreSQL and verifies that the
    authenticated principal has site/organization access to that endpoint.
    """
    stmt = (
        select(Agent, Site.org_id)
        .join(Site, Agent.site_id == Site.id)
        .where(Agent.id == agent_id)
    )
    row = (await db.execute(stmt)).first()

    if not row:
        if (
            allow_unregistered_for_unscoped
            and principal.site_id is None
            and principal.org_id is None
        ):
            return None
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found.",
        )

    agent, site_org_id = row[0], row[1]
    if not principal.can_access_site(agent.site_id, site_org_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied: agent '{agent_id}' belongs to site '{agent.site_id}', "
                f"outside the scope of role '{principal.role.value}'."
            ),
        )
    return agent


async def authenticate_ws_operator(
    websocket: WebSocket,
    query_token: Optional[str] = None,
) -> Optional[Principal]:
    """
    Authenticates an operator WebSocket handshake from Authorization header,
    X-API-Key header, or `?token=` query parameter, returning the resolved Principal.
    """
    auth_header = websocket.headers.get("authorization")
    api_key_header = websocket.headers.get("x-api-key")
    candidate = extract_bearer_token(auth_header, api_key_header) or query_token
    if not candidate:
        return None

    principal = await resolve_principal_from_token(candidate)
    if not principal or not principal.is_active:
        return None
    if not principal.has_permission(Permission.WS_CONNECT):
        return None
    return principal


async def verify_ws_agent_access(principal: Principal, agent_id: UUID) -> bool:
    """
    Verifies whether an operator WebSocket principal has site/organization permission
    to connect to the specified agent's C2 tunnel.
    """
    if (
        principal.role == Role.SUPER_ADMIN
        and principal.site_id is None
        and principal.org_id is None
    ):
        return True

    async with async_session_factory() as db:
        stmt = (
            select(Agent.site_id, Site.org_id)
            .join(Site, Agent.site_id == Site.id)
            .where(Agent.id == agent_id)
        )
        row = (await db.execute(stmt)).first()
        if not row:
            # If the principal is strictly scoped to a site/org, deny unknown agents
            if principal.site_id is not None or principal.org_id is not None:
                return False
            return True
        agent_site_id, site_org_id = row[0], row[1]
        return principal.can_access_site(agent_site_id, site_org_id)


def verify_ws_dispatch_permission(principal: Optional[Principal]) -> bool:
    """
    Checks whether the WebSocket principal is permitted to dispatch commands
    or interactive terminal input (`term_in` / `task_dispatch`) to an agent.
    """
    if principal is None or not principal.is_active:
        return False
    return principal.has_permission(Permission.WS_DISPATCH) and principal.has_permission(
        Permission.AGENT_DISPATCH
    )


def _required_permission_for_request(method: str, path: str) -> Optional[Permission]:
    """
    Maps control-plane REST request (method, path) pairs to their required RBAC Permission
    for middleware-level enforcement.
    """
    m = method.upper()
    norm_path = path.rstrip("/") or "/"

    # Organizations
    if norm_path.startswith("/api/v1/organizations"):
        return Permission.ORG_READ if m == "GET" else Permission.ORG_WRITE

    # Sites
    if norm_path.startswith("/api/v1/sites"):
        return Permission.SITE_READ if m == "GET" else Permission.SITE_WRITE

    # Enrollment Tokens
    if norm_path.startswith("/api/v1/tokens"):
        return Permission.TOKEN_READ if m == "GET" else Permission.TOKEN_WRITE

    # Agents & Task Dispatch
    if norm_path.startswith("/api/v1/agents"):
        if m == "GET":
            return Permission.AGENT_READ
        if norm_path.endswith("/tasks") and m == "POST":
            return Permission.AGENT_DISPATCH
        return Permission.AGENT_WRITE

    # Script Keystore & Rendering
    if norm_path.startswith("/api/v1/scripts"):
        if m == "GET":
            return Permission.SCRIPT_READ
        if norm_path.endswith("/render") and m == "POST":
            return Permission.SCRIPT_EXECUTE
        return Permission.SCRIPT_WRITE

    # Cryptographic Keys
    if norm_path.startswith("/api/v1/keys"):
        if norm_path.endswith("/verify") and m == "POST":
            return Permission.KEY_VERIFY
        if norm_path.endswith("/sign") and m == "POST":
            return Permission.KEY_SIGN
        if norm_path.endswith("/rotate") and m == "POST":
            return Permission.KEY_ROTATE
        return Permission.KEY_READ

    # RBAC Users / Roles introspection
    if norm_path.startswith("/api/v1/users") or norm_path.startswith("/api/v1/rbac"):
        if norm_path.endswith("/me") or norm_path.endswith("/roles"):
            return None  # Allowed for any authenticated active principal
        return Permission.USER_READ if m == "GET" else Permission.USER_WRITE

    # Immutable Security Audit Logs
    if norm_path.startswith("/api/v1/audit"):
        return Permission.AUDIT_READ

    return None


class RBACMiddleware(BaseHTTPMiddleware):
    """
    ASGI Middleware enforcing Role-Based Access Control (RBAC) across all
    control-plane REST endpoints:
    1. Bypasses public and agent-authenticated endpoints.
    2. Authenticates the operator bearer token and caches `request.state.principal`.
    3. Blocks disabled accounts and enforces role/permission boundaries (e.g. read-only Auditor).
    4. Attaches `X-RBAC-Role` metadata header to responses.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method.upper()

        # Pass through CORS preflight, non-API paths, and public/agent-authenticated routes
        if (
            method == "OPTIONS"
            or not path.startswith("/api/v1")
            or path.rstrip("/") in _PUBLIC_EXACT_PATHS
            or _AGENT_HEARTBEAT_RE.match(path)
        ):
            return await call_next(request)

        # If a test has registered a dependency override for get_current_principal,
        # let FastAPI's route dependency injection handle authentication and RBAC.
        if get_current_principal in getattr(request.app, "dependency_overrides", {}):
            return await call_next(request)

        raw_token = extract_bearer_token(
            request.headers.get("authorization"),
            request.headers.get("x-api-key"),
        )
        if not raw_token:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or missing operator authentication credentials."},
                headers={"WWW-Authenticate": "Bearer"},
            )

        principal = await resolve_principal_from_token(raw_token)
        if not principal:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid or missing operator authentication credentials."},
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not principal.is_active:
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Operator account is disabled."},
            )

        request.state.principal = principal

        # Enforce required permission for matched route & HTTP method
        required_perm = _required_permission_for_request(method, path)
        if required_perm is not None and not principal.has_permission(required_perm):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": (
                        f"Permission denied: role '{principal.role.value}' lacks required "
                        f"permission(s): {required_perm.value}."
                    )
                },
            )

        response = await call_next(request)
        response.headers["X-RBAC-Role"] = principal.role.value
        return response
