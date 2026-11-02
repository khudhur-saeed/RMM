from datetime import datetime
from typing import Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

ShellType = Literal["powershell", "bash", "cmd"]


def _normalize_tags(tags: List[str]) -> List[str]:
    """Normalizes tags to lowercase, stripped, deduplicated strings while preserving order."""
    seen: set[str] = set()
    normalized: List[str] = []
    for tag in tags:
        clean = tag.strip().lower()
        if clean and clean not in seen:
            if len(clean) > 64:
                clean = clean[:64]
            seen.add(clean)
            normalized.append(clean)
    return normalized


class ScriptParameter(BaseModel):
    """Defines a typed runtime parameter for template interpolation ({{NAME}})."""
    name: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$",
        description="Parameter variable identifier matching {{NAME}} in script content",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Human-readable explanation of the parameter",
    )
    default_value: Optional[str] = Field(
        default=None,
        max_length=1024,
        description="Fallback value used when not explicitly supplied at runtime",
    )
    required: bool = Field(
        default=True,
        description="Whether execution must fail if no value or default_value is available",
    )


class ScriptBase(BaseModel):
    """Shared properties across Script Keystore schemas."""
    name: str = Field(
        ...,
        min_length=1,
        max_length=150,
        description="Unique display name of the script in the keystore",
    )
    description: Optional[str] = Field(
        default=None,
        max_length=500,
        description="Operational summary and usage notes",
    )
    shell_type: ShellType = Field(
        ...,
        description="Target execution interpreter: powershell, bash, or cmd",
    )
    content: str = Field(
        ...,
        min_length=1,
        description="Raw script body supporting {{PARAMETER}} template placeholders",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Categorization tags (e.g. ['remediation', 'linux', 'network'])",
    )
    parameters: List[ScriptParameter] = Field(
        default_factory=list,
        description="Declared runtime parameters for template rendering",
    )
    timeout_sec: int = Field(
        default=60,
        ge=1,
        le=3600,
        description="Maximum execution timeout in seconds",
    )

    @field_validator("tags")
    @classmethod
    def validate_and_normalize_tags(cls, v: List[str]) -> List[str]:
        return _normalize_tags(v)


class ScriptCreate(ScriptBase):
    """Inbound validation schema for creating a new script."""
    pass


class ScriptUpdate(BaseModel):
    """Inbound validation schema for updating an existing script."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=150)
    description: Optional[str] = Field(default=None, max_length=500)
    shell_type: Optional[ShellType] = None
    content: Optional[str] = Field(default=None, min_length=1)
    tags: Optional[List[str]] = None
    parameters: Optional[List[ScriptParameter]] = None
    timeout_sec: Optional[int] = Field(default=None, ge=1, le=3600)

    @field_validator("tags")
    @classmethod
    def validate_and_normalize_tags(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return None
        return _normalize_tags(v)


class ScriptRead(ScriptBase):
    """Outbound serialization schema for stored scripts."""
    id: UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScriptRenderRequest(BaseModel):
    """Inbound payload for rendering a parameterized script and optionally dispatching it."""
    values: Dict[str, str] = Field(
        default_factory=dict,
        description="Key-value map of parameter names to runtime values",
    )
    agent_id: Optional[UUID] = Field(
        default=None,
        description="Optional connected agent UUID to immediately dispatch the rendered task to",
    )


class ScriptRenderResponse(BaseModel):
    """Outbound response containing the interpolated script body and optional task dispatch ID."""
    script_id: UUID
    name: str
    shell_type: ShellType
    rendered_command: str
    timeout_sec: int
    dispatched_task_id: Optional[UUID] = None
