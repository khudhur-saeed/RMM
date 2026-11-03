import re
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import (
    compute_payload_digest,
    compute_task_digest,
    sign_payload,
    sign_task_dispatch,
)
from app.core.security import verify_operator_token
from app.core.ws_manager import ws_manager
from app.db.session import get_db
from app.models.script import Script
from app.schemas.script import (
    ScriptCreate,
    ScriptParameter,
    ScriptRead,
    ScriptRenderRequest,
    ScriptRenderResponse,
    ScriptUpdate,
    ShellType,
)
from app.schemas.task import TaskDispatchFrame

router = APIRouter(dependencies=[Depends(verify_operator_token)])

PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


def _merge_extracted_parameters(
    content: str,
    declared: List[ScriptParameter],
) -> List[Dict[str, Any]]:
    """
    Combines explicitly declared parameters with any undeclared {{PARAM}}
    placeholders discovered in the script content.
    """
    merged: List[Dict[str, Any]] = []
    seen: set[str] = set()

    for param in declared:
        if param.name not in seen:
            seen.add(param.name)
            merged.append(param.model_dump())

    for match in PLACEHOLDER_PATTERN.finditer(content):
        var_name = match.group(1)
        if var_name not in seen:
            seen.add(var_name)
            merged.append(
                ScriptParameter(
                    name=var_name,
                    description=f"Auto-detected template parameter {{{{{var_name}}}}}",
                    default_value=None,
                    required=True,
                ).model_dump()
            )

    return merged


def _render_script_content(
    content: str,
    parameters: List[Dict[str, Any]],
    runtime_values: Dict[str, str],
) -> str:
    """
    Interpolates {{PARAM}} placeholders in script content using runtime_values
    with fallback to declared parameter default_value.
    Raises HTTP 422 if any required or undeclared parameter is missing.
    """
    resolved: Dict[str, str] = {}
    missing: List[str] = []

    for param in parameters:
        name = param.get("name")
        if not name:
            continue
        default_val = param.get("default_value")
        is_required = param.get("required", True)

        if name in runtime_values and runtime_values[name] is not None:
            resolved[name] = str(runtime_values[name])
        elif default_val is not None:
            resolved[name] = str(default_val)
        elif is_required:
            missing.append(name)
        else:
            resolved[name] = ""

    # Include any additional runtime values provided by the caller
    for key, val in runtime_values.items():
        if key not in resolved and val is not None:
            resolved[key] = str(val)

    # Check if any placeholder in content is still unresolved
    for match in PLACEHOLDER_PATTERN.finditer(content):
        var_name = match.group(1)
        if var_name not in resolved and var_name not in missing:
            missing.append(var_name)

    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Missing required script parameter(s): {', '.join(missing)}",
        )

    def _replace(match: re.Match) -> str:
        var_name = match.group(1)
        return resolved.get(var_name, "")

    return PLACEHOLDER_PATTERN.sub(_replace, content)


@router.post(
    "",
    response_model=ScriptRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create and store a new PowerShell, Bash, or CMD script in the keystore",
)
async def create_script(
    payload: ScriptCreate,
    db: AsyncSession = Depends(get_db),
):
    """Stores a tagged, parameterized script in the PostgreSQL Script Keystore."""
    merged_params = _merge_extracted_parameters(payload.content, payload.parameters)

    script = Script(
        name=payload.name.strip(),
        description=payload.description,
        shell_type=payload.shell_type,
        content=payload.content,
        tags=payload.tags,
        parameters=merged_params,
        timeout_sec=payload.timeout_sec,
    )
    db.add(script)
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A script with the name '{payload.name.strip()}' already exists.",
        )

    await db.refresh(script)
    return script


@router.get(
    "",
    response_model=List[ScriptRead],
    status_code=status.HTTP_200_OK,
    summary="List and filter scripts in the keystore by tag, shell type, or search query",
)
async def list_scripts(
    tag: Optional[str] = Query(
        default=None,
        description="Filter scripts containing a specific tag (case-insensitive)",
    ),
    shell_type: Optional[ShellType] = Query(
        default=None,
        description="Filter scripts by target interpreter (powershell, bash, cmd)",
    ),
    search: Optional[str] = Query(
        default=None,
        description="Case-insensitive substring search across script name and description",
    ),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves stored scripts ordered alphabetically by name."""
    stmt = select(Script)

    if tag and tag.strip():
        normalized_tag = tag.strip().lower()
        stmt = stmt.where(Script.tags.any(normalized_tag))

    if shell_type:
        stmt = stmt.where(Script.shell_type == shell_type)

    if search and search.strip():
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Script.name.ilike(pattern),
                Script.description.ilike(pattern),
            )
        )

    stmt = stmt.order_by(Script.name.asc()).offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get(
    "/{script_id}",
    response_model=ScriptRead,
    status_code=status.HTTP_200_OK,
    summary="Get a single script from the keystore by UUID",
)
async def get_script(
    script_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Retrieves full script content, tags, and parameter metadata by ID."""
    stmt = select(Script).where(Script.id == script_id)
    script = (await db.execute(stmt)).scalar_one_or_none()
    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Script not found.",
        )
    return script


@router.put(
    "/{script_id}",
    response_model=ScriptRead,
    status_code=status.HTTP_200_OK,
    summary="Update an existing script in the keystore",
)
@router.patch(
    "/{script_id}",
    response_model=ScriptRead,
    status_code=status.HTTP_200_OK,
    summary="Partially update an existing script in the keystore",
)
async def update_script(
    script_id: UUID,
    payload: ScriptUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Updates script fields, normalizes tags, and refreshes template parameter definitions."""
    stmt = select(Script).where(Script.id == script_id)
    script = (await db.execute(stmt)).scalar_one_or_none()
    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Script not found.",
        )

    update_data = payload.model_dump(exclude_unset=True)

    if "name" in update_data and update_data["name"] is not None:
        script.name = update_data["name"].strip()
    if "description" in update_data:
        script.description = update_data["description"]
    if "shell_type" in update_data and update_data["shell_type"] is not None:
        script.shell_type = update_data["shell_type"]
    if "content" in update_data and update_data["content"] is not None:
        script.content = update_data["content"]
    if "tags" in update_data and update_data["tags"] is not None:
        script.tags = update_data["tags"]
    if "timeout_sec" in update_data and update_data["timeout_sec"] is not None:
        script.timeout_sec = update_data["timeout_sec"]

    # Re-evaluate parameters if content or parameters changed
    if "parameters" in update_data and update_data["parameters"] is not None:
        declared_params = [ScriptParameter(**p) if isinstance(p, dict) else p for p in payload.parameters or []]
        script.parameters = _merge_extracted_parameters(script.content, declared_params)
    elif "content" in update_data and update_data["content"] is not None:
        existing_params = [ScriptParameter(**p) for p in (script.parameters or [])]
        script.parameters = _merge_extracted_parameters(script.content, existing_params)

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A script with the name '{script.name}' already exists.",
        )

    await db.refresh(script)
    return script


@router.delete(
    "/{script_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a script from the keystore",
)
async def delete_script(
    script_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """Permanently removes a script from the keystore."""
    stmt = select(Script).where(Script.id == script_id)
    script = (await db.execute(stmt)).scalar_one_or_none()
    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Script not found.",
        )

    await db.delete(script)
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{script_id}/render",
    response_model=ScriptRenderResponse,
    status_code=status.HTTP_200_OK,
    summary="Render a parameterized script with runtime values and optionally dispatch to an agent",
)
async def render_script(
    script_id: UUID,
    payload: ScriptRenderRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Substitutes {{PARAMETER}} placeholders in the stored script using provided runtime values
    (or declared defaults). If agent_id is supplied, dispatches the rendered script over the
    live C2 WebSocket tunnel as a TaskDispatchFrame.
    """
    stmt = select(Script).where(Script.id == script_id)
    script = (await db.execute(stmt)).scalar_one_or_none()
    if not script:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Script not found.",
        )

    rendered_command = _render_script_content(
        content=script.content,
        parameters=script.parameters or [],
        runtime_values=payload.values,
    )

    dispatched_task_id: Optional[UUID] = None
    payload_sha256: str
    signature: str
    if payload.agent_id is not None:
        task_id = uuid4()
        payload_sha256 = compute_task_digest(
            task_id=task_id,
            command=rendered_command,
            timeout_sec=script.timeout_sec,
        )
        signature = sign_task_dispatch(
            task_id=task_id,
            command=rendered_command,
            timeout_sec=script.timeout_sec,
        )
        task_frame = TaskDispatchFrame(
            task_id=task_id,
            command=rendered_command,
            timeout_sec=script.timeout_sec,
            payload_sha256=payload_sha256,
            signature=signature,
        )
        routed = await ws_manager.route_to_agent(
            payload.agent_id,
            task_frame.model_dump_json(),
        )
        if not routed:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Target agent is not currently connected to the C2 tunnel.",
            )
        dispatched_task_id = task_frame.task_id
    else:
        payload_sha256 = compute_payload_digest(rendered_command)
        signature = sign_payload(rendered_command)

    return ScriptRenderResponse(
        script_id=script.id,
        name=script.name,
        shell_type=script.shell_type,  # type: ignore[arg-type]
        rendered_command=rendered_command,
        timeout_sec=script.timeout_sec,
        payload_sha256=payload_sha256,
        signature=signature,
        dispatched_task_id=dispatched_task_id,
    )
