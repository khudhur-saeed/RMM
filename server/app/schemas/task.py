from typing import Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class TaskDispatchFrame(BaseModel):
    """C2 command dispatch contract: Orchestrator -> Agent."""
    type: str = Field(default="task_dispatch")
    task_id: UUID
    command: str = Field(..., min_length=1, description="Shell command string to execute")
    timeout_sec: int = Field(default=30, gt=0, description="Execution timeout budget in seconds")
    signature: Optional[str] = Field(
        default=None,
        description="Base64-encoded Ed25519 signature over <task_id>:<timeout_sec>:<command>",
    )


class TaskStreamFrame(BaseModel):
    """Live streaming chunk contract: Agent -> Orchestrator."""
    type: str = Field(default="task_stream")
    task_id: UUID
    stream: Literal["stdout", "stderr"]
    chunk: str


class TaskExitFrame(BaseModel):
    """Execution completion contract: Agent -> Orchestrator."""
    type: str = Field(default="task_exit")
    task_id: UUID
    exit_code: int
    elapsed_ms: int = Field(..., ge=0)
    error: Optional[str] = None