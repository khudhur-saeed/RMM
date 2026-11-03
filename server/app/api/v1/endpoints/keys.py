from fastapi import APIRouter, Depends, HTTPException, status

from app.core.crypto import (
    Ed25519KeyPair,
    compute_payload_digest,
    get_signing_keypair,
    load_public_key,
    sign_payload,
    signing_key_manager,
    verify_signature,
)
from app.core.security import verify_operator_token
from app.schemas.crypto import (
    PublicKeyRead,
    SignPayloadRequest,
    SignPayloadResponse,
    VerifySignatureRequest,
    VerifySignatureResponse,
)

router = APIRouter()


def _serialize_public_key(keypair: Ed25519KeyPair) -> PublicKeyRead:
    return PublicKeyRead(
        algorithm="Ed25519",
        public_key_b64=keypair.public_key_b64,
        public_key_pem=keypair.public_key_pem,
        fingerprint_sha256=keypair.fingerprint_sha256,
    )


@router.get(
    "/public",
    response_model=PublicKeyRead,
    status_code=status.HTTP_200_OK,
    summary="Retrieve the server's active Ed25519 verification public key for agents",
)
async def get_public_verification_key():
    """
    Returns the control plane's active Ed25519 public key in both Base64 raw (32-byte)
    and SubjectPublicKeyInfo PEM formats so endpoint agents can verify signed tasks/scripts.
    """
    keypair = get_signing_keypair()
    return _serialize_public_key(keypair)


@router.post(
    "/rotate",
    response_model=PublicKeyRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_operator_token)],
    summary="Generate and persist a new Ed25519 signing keypair",
)
async def rotate_signing_key():
    """
    Generates a fresh Ed25519 private signing key on the server, atomically persists it
    to secure storage, and returns the new agent verification public key.
    """
    keypair = signing_key_manager.rotate_keypair()
    return _serialize_public_key(keypair)


@router.post(
    "/sign",
    response_model=SignPayloadResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_operator_token)],
    summary="Sign a script or task payload using the server's Ed25519 private key",
)
async def sign_script_payload(
    request: SignPayloadRequest,
):
    """Computes the SHA-256 digest and signs the provided UTF-8 payload string with the server's active Ed25519 private key."""
    keypair = get_signing_keypair()
    digest = compute_payload_digest(request.payload)
    sig_b64 = sign_payload(request.payload, private_key=keypair.private_key)
    return SignPayloadResponse(
        algorithm="Ed25519",
        payload_sha256=digest,
        signature_b64=sig_b64,
        public_key_b64=keypair.public_key_b64,
        fingerprint_sha256=keypair.fingerprint_sha256,
    )


@router.post(
    "/verify",
    response_model=VerifySignatureResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_operator_token)],
    summary="Verify an Ed25519 signature using the agent verification public key",
)
async def verify_script_signature(
    request: VerifySignatureRequest,
):
    """
    Verifies a Base64-encoded Ed25519 signature against the provided payload
    and either an explicit public key or the server's active verification public key.
    """
    if request.public_key:
        try:
            pub = load_public_key(request.public_key)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            )
        # Compute fingerprint of caller-provided public key
        import hashlib
        from cryptography.hazmat.primitives import serialization
        raw_pub = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = hashlib.sha256(raw_pub).hexdigest()
        is_valid = verify_signature(request.payload, request.signature_b64, public_key=pub)
    else:
        keypair = get_signing_keypair()
        fingerprint = keypair.fingerprint_sha256
        is_valid = verify_signature(
            request.payload,
            request.signature_b64,
            public_key=keypair.public_key,
        )

    return VerifySignatureResponse(
        valid=is_valid,
        algorithm="Ed25519",
        fingerprint_sha256=fingerprint,
    )
