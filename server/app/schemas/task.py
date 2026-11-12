from typing import Literal, Optional
from uuid import UUID
from pydantic import BaseModel, Field


class TaskDispatchFrame(BaseModel):
    """C2 command dispatch contract: Orchestrator -> Agent."""
    type: str = Field(default="task_dispatch")
    task_id: UUID
    agent_id: Optional[UUID] = Field(
        default=None,
        description="Target agent UUID cryptographically bound to this dispatch",
    )
    issued_at: Optional[int] = Field(
        default=None,
        description="UTC epoch timestamp (seconds) when the task was signed",
    )
    expires_at: Optional[int] = Field(
        default=None,
        description="UTC epoch timestamp (seconds) after which the signature expires",
    )
    nonce: Optional[str] = Field(
        default=None,
        description="Cryptographic random hex nonce preventing capture-replay",
    )
    command: str = Field(..., min_length=1, description="Shell command string to execute")
    timeout_sec: int = Field(default=30, gt=0, description="Execution timeout budget in seconds")
    payload_sha256: Optional[str] = Field(
        default=None,
        description="Hex-encoded SHA-256 digest over canonical task payload",
    )
    signature: Optional[str] = Field(
        default=None,
        description="Base64-encoded Ed25519 signature over canonical task payload",
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
