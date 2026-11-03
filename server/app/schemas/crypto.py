from typing import Literal, Optional
from pydantic import BaseModel, Field


class PublicKeyRead(BaseModel):
    """
    Outbound schema exposing the server's Ed25519 verification public key
    for endpoint agents to verify signed scripts and C2 tasks.
    """
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_b64: str = Field(
        ...,
        description="Base64-encoded 32-byte raw Ed25519 public key (compatible with Go crypto/ed25519)",
    )
    public_key_pem: str = Field(
        ...,
        description="SubjectPublicKeyInfo PEM-encoded Ed25519 public key",
    )
    fingerprint_sha256: str = Field(
        ...,
        description="SHA-256 hex digest of the raw 32-byte Ed25519 public key",
    )


class SignPayloadRequest(BaseModel):
    """Inbound request for signing a script or command payload with the server's Ed25519 private key."""
    payload: str = Field(
        ...,
        min_length=1,
        description="UTF-8 string content (e.g. script body or canonical task string) to sign",
    )


class SignPayloadResponse(BaseModel):
    """Outbound response containing the Ed25519 detached signature and verification public key metadata."""
    algorithm: Literal["Ed25519"] = "Ed25519"
    signature_b64: str = Field(
        ...,
        description="Base64-encoded 64-byte Ed25519 signature",
    )
    public_key_b64: str = Field(
        ...,
        description="Base64-encoded 32-byte raw Ed25519 public key corresponding to the signing key",
    )
    fingerprint_sha256: str


class VerifySignatureRequest(BaseModel):
    """Inbound request to verify an Ed25519 signature against a payload and agent verification public key."""
    payload: str = Field(
        ...,
        min_length=1,
        description="UTF-8 string content that was signed",
    )
    signature_b64: str = Field(
        ...,
        min_length=1,
        description="Base64-encoded 64-byte Ed25519 signature to verify",
    )
    public_key: Optional[str] = Field(
        default=None,
        description="Optional PEM or Base64 Ed25519 public key (defaults to server's active public key)",
    )


class VerifySignatureResponse(BaseModel):
    """Outbound verification result."""
    valid: bool
    algorithm: Literal["Ed25519"] = "Ed25519"
    fingerprint_sha256: str
