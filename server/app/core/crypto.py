import base64
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import time
from typing import Any, Dict, Optional, Union
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.core.config import settings

PRIVATE_KEY_FILENAME = "ed25519_signing.key"
PUBLIC_KEY_FILENAME = "ed25519_signing.pub"
MAX_CLOCK_SKEW_SEC = 300


@dataclass(frozen=True)
class Ed25519KeyPair:
    """
    Encapsulates an Ed25519 private signing key and its corresponding
    public verification key (distributed to endpoint agents).
    """
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @property
    def private_key_pem(self) -> str:
        """Exports the Ed25519 private key in unencrypted PKCS#8 PEM format."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

    @property
    def public_key_pem(self) -> str:
        """Exports the Ed25519 verification public key in SubjectPublicKeyInfo PEM format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    @property
    def private_key_b64(self) -> str:
        """Exports the raw 32-byte Ed25519 private seed encoded as standard Base64."""
        raw_seed = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return base64.b64encode(raw_seed).decode("ascii")

    @property
    def public_key_b64(self) -> str:
        """
        Exports the raw 32-byte Ed25519 public key encoded as standard Base64.
        Directly compatible with Go's `crypto/ed25519.PublicKey` after Base64 decoding.
        """
        raw_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw_pub).decode("ascii")

    @property
    def fingerprint_sha256(self) -> str:
        """Returns the SHA-256 hex digest of the raw 32-byte public key."""
        raw_pub = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return hashlib.sha256(raw_pub).hexdigest()


def generate_ed25519_keypair() -> Ed25519KeyPair:
    """
    Generates a fresh Ed25519 private signing key for the server and derives
    the corresponding public key for endpoint agent verification.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return Ed25519KeyPair(private_key=private_key, public_key=public_key)


def load_private_key(key_material: Union[str, bytes]) -> Ed25519PrivateKey:
    """
    Loads an Ed25519PrivateKey from either a PKCS#8 PEM string/bytes
    or a Base64-encoded 32-byte raw seed.
    """
    raw_bytes = key_material.encode("utf-8") if isinstance(key_material, str) else key_material
    stripped = raw_bytes.strip()

    if stripped.startswith(b"-----BEGIN"):
        loaded = serialization.load_pem_private_key(stripped, password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError("Provided PEM key is not an Ed25519 private key.")
        return loaded

    try:
        seed = base64.b64decode(stripped, validate=True)
    except Exception as exc:
        raise ValueError("Invalid Ed25519 private key encoding; expected PEM or Base64 seed.") from exc

    if len(seed) != 32:
        raise ValueError(f"Invalid Ed25519 private key seed length: expected 32 bytes, got {len(seed)}.")

    return Ed25519PrivateKey.from_private_bytes(seed)


def load_public_key(key_material: Union[str, bytes]) -> Ed25519PublicKey:
    """
    Loads an Ed25519PublicKey from either a SubjectPublicKeyInfo PEM string/bytes
    or a Base64-encoded 32-byte raw public key.
    """
    raw_bytes = key_material.encode("utf-8") if isinstance(key_material, str) else key_material
    stripped = raw_bytes.strip()

    if stripped.startswith(b"-----BEGIN"):
        loaded = serialization.load_pem_public_key(stripped)
        if not isinstance(loaded, Ed25519PublicKey):
            raise ValueError("Provided PEM key is not an Ed25519 public key.")
        return loaded

    try:
        pub_bytes = base64.b64decode(stripped, validate=True)
    except Exception as exc:
        raise ValueError("Invalid Ed25519 public key encoding; expected PEM or Base64 raw bytes.") from exc

    if len(pub_bytes) != 32:
        raise ValueError(f"Invalid Ed25519 public key length: expected 32 bytes, got {len(pub_bytes)}.")

    return Ed25519PublicKey.from_public_bytes(pub_bytes)


class SigningKeyManager:
    """
    Manages the lifecycle, disk persistence, and rotation of the server's
    Ed25519 code-signing private key and agent verification public key.
    """

    def __init__(self, key_dir: Optional[Union[str, Path]] = None) -> None:
        self._key_dir = Path(key_dir or settings.SIGNING_KEY_DIR)
        self._cached_keypair: Optional[Ed25519KeyPair] = None

    @property
    def private_key_path(self) -> Path:
        return self._key_dir / PRIVATE_KEY_FILENAME

    @property
    def public_key_path(self) -> Path:
        return self._key_dir / PUBLIC_KEY_FILENAME

    def get_or_create_keypair(self) -> Ed25519KeyPair:
        """
        Returns the active Ed25519KeyPair, loading it from environment configuration,
        existing disk storage, or generating and persisting a new keypair if absent.
        """
        if self._cached_keypair is not None:
            return self._cached_keypair

        # 1. Prefer explicit environment secret if configured
        if settings.ED25519_PRIVATE_KEY:
            priv = load_private_key(settings.ED25519_PRIVATE_KEY)
            self._cached_keypair = Ed25519KeyPair(private_key=priv, public_key=priv.public_key())
            return self._cached_keypair

        # 2. Load from persistent key directory if already generated
        if self.private_key_path.exists():
            pem_bytes = self.private_key_path.read_bytes()
            priv = load_private_key(pem_bytes)
            keypair = Ed25519KeyPair(private_key=priv, public_key=priv.public_key())
            # Ensure public key file stays synchronized
            if not self.public_key_path.exists():
                self._write_public_key(keypair)
            self._cached_keypair = keypair
            return self._cached_keypair

        # 3. Generate and atomically persist a new Ed25519 keypair
        return self.rotate_keypair()

    def rotate_keypair(self) -> Ed25519KeyPair:
        """
        Generates a brand-new Ed25519 keypair, atomically persists both private (0600)
        and public (0644) PEM files to disk, and updates the in-memory cache.
        """
        keypair = generate_ed25519_keypair()
        self._persist_keypair(keypair)
        self._cached_keypair = keypair
        return keypair

    def _persist_keypair(self, keypair: Ed25519KeyPair) -> None:
        self._key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        tmp_priv = self.private_key_path.with_suffix(".key.tmp")
        fd = os.open(str(tmp_priv), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(keypair.private_key_pem)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_priv, 0o600)
            os.replace(tmp_priv, self.private_key_path)
        finally:
            if tmp_priv.exists():
                tmp_priv.unlink(missing_ok=True)

        self._write_public_key(keypair)

    def _write_public_key(self, keypair: Ed25519KeyPair) -> None:
        self._key_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp_pub = self.public_key_path.with_suffix(".pub.tmp")
        tmp_pub.write_text(keypair.public_key_pem, encoding="utf-8")
        os.chmod(tmp_pub, 0o644)
        os.replace(tmp_pub, self.public_key_path)


signing_key_manager = SigningKeyManager()


def get_signing_keypair() -> Ed25519KeyPair:
    """Returns the server's active Ed25519 signing/verification keypair."""
    return signing_key_manager.get_or_create_keypair()


def _has_scope_binding(
    agent_id: Optional[Union[UUID, str]],
    issued_at: Optional[int],
    expires_at: Optional[int],
    nonce: Optional[str],
) -> bool:
    return bool(
        (agent_id is not None and str(agent_id).strip() != "")
        or (nonce is not None and str(nonce).strip() != "")
        or (issued_at is not None and int(issued_at) != 0)
        or (expires_at is not None and int(expires_at) != 0)
    )


def build_canonical_task_payload(
    task_id: Union[UUID, str],
    command: str,
    timeout_sec: int,
    agent_id: Optional[Union[UUID, str]] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    nonce: Optional[str] = None,
) -> bytes:
    """
    Constructs a deterministic canonical byte sequence for signing C2 task/script dispatches.
    When recipient/freshness binding fields are provided:
    `<agent_id>:<task_id>:<issued_at>:<expires_at>:<nonce>:<timeout_sec>:<command>` encoded as UTF-8.
    """
    norm_task = str(task_id).strip().lower()
    if _has_scope_binding(agent_id, issued_at, expires_at, nonce):
        norm_agent = str(agent_id).strip().lower() if agent_id is not None else ""
        norm_nonce = str(nonce).strip() if nonce is not None else ""
        return (
            f"{norm_agent}:{norm_task}:{int(issued_at or 0)}:{int(expires_at or 0)}:"
            f"{norm_nonce}:{int(timeout_sec)}:{command}"
        ).encode("utf-8")
    return f"{norm_task}:{int(timeout_sec)}:{command}".encode("utf-8")


def build_canonical_term_in_payload(
    agent_id: Union[UUID, str],
    issued_at: int,
    expires_at: int,
    nonce: str,
    payload: str,
) -> bytes:
    """
    Constructs the domain-separated deterministic byte sequence for signed interactive terminal input:
    `term_in:<agent_id>:<issued_at>:<expires_at>:<nonce>:<payload>` encoded as UTF-8.
    """
    norm_agent = str(agent_id).strip().lower()
    norm_nonce = str(nonce).strip()
    return f"term_in:{norm_agent}:{int(issued_at)}:{int(expires_at)}:{norm_nonce}:{payload}".encode("utf-8")


def compute_payload_digest(data: Union[bytes, str]) -> str:
    """Computes the lowercase hex-encoded SHA-256 digest of a raw byte or UTF-8 string payload."""
    payload_bytes = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload_bytes).hexdigest()


def compute_task_digest(
    task_id: Union[UUID, str],
    command: str,
    timeout_sec: int,
    agent_id: Optional[Union[UUID, str]] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    nonce: Optional[str] = None,
) -> str:
    """Computes the lowercase hex-encoded SHA-256 digest of the canonical C2 task payload."""
    canonical = build_canonical_task_payload(
        task_id=task_id,
        command=command,
        timeout_sec=timeout_sec,
        agent_id=agent_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )
    return compute_payload_digest(canonical)


def compute_term_in_digest(
    agent_id: Union[UUID, str],
    issued_at: int,
    expires_at: int,
    nonce: str,
    payload: str,
) -> str:
    """Computes the lowercase hex-encoded SHA-256 digest of the canonical terminal input payload."""
    canonical = build_canonical_term_in_payload(
        agent_id=agent_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        payload=payload,
    )
    return compute_payload_digest(canonical)


def sign_payload(
    data: Union[bytes, str],
    private_key: Optional[Union[Ed25519PrivateKey, str]] = None,
) -> str:
    """
    Signs arbitrary payload bytes (or UTF-8 string) using the Ed25519 private key
    and returns a Base64-encoded 64-byte signature.
    """
    payload_bytes = data.encode("utf-8") if isinstance(data, str) else data

    if private_key is None:
        priv = get_signing_keypair().private_key
    elif isinstance(private_key, str):
        priv = load_private_key(private_key)
    else:
        priv = private_key

    signature = priv.sign(payload_bytes)
    return base64.b64encode(signature).decode("ascii")


def verify_signature(
    data: Union[bytes, str],
    signature_b64: str,
    public_key: Optional[Union[Ed25519PublicKey, str]] = None,
) -> bool:
    """
    Verifies a Base64-encoded Ed25519 signature against `data` using the agent
    verification public key (defaults to the server's active public key).
    Returns True if authentic, or False if tampered/invalid.
    """
    payload_bytes = data.encode("utf-8") if isinstance(data, str) else data

    try:
        sig_bytes = base64.b64decode(signature_b64.strip(), validate=True)
        if len(sig_bytes) != 64:
            return False

        if public_key is None:
            pub = get_signing_keypair().public_key
        elif isinstance(public_key, str):
            pub = load_public_key(public_key)
        else:
            pub = public_key

        pub.verify(sig_bytes, payload_bytes)
        return True
    except (InvalidSignature, ValueError, Exception):
        return False


def sign_task_dispatch(
    task_id: Union[UUID, str],
    command: str,
    timeout_sec: int,
    private_key: Optional[Union[Ed25519PrivateKey, str]] = None,
    agent_id: Optional[Union[UUID, str]] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    nonce: Optional[str] = None,
) -> str:
    """Signs a C2 task/script dispatch frame using the canonical task payload format."""
    canonical = build_canonical_task_payload(
        task_id=task_id,
        command=command,
        timeout_sec=timeout_sec,
        agent_id=agent_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )
    return sign_payload(canonical, private_key=private_key)


def sign_term_in(
    agent_id: Union[UUID, str],
    issued_at: int,
    expires_at: int,
    nonce: str,
    payload: str,
    private_key: Optional[Union[Ed25519PrivateKey, str]] = None,
) -> str:
    """Signs an interactive terminal input frame (`term_in`) using the domain-separated canonical payload."""
    canonical = build_canonical_term_in_payload(
        agent_id=agent_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
        payload=payload,
    )
    return sign_payload(canonical, private_key=private_key)


def build_signed_term_in_frame(
    agent_id: Union[UUID, str],
    payload: str,
    ttl_sec: int = 120,
) -> Dict[str, Any]:
    """Builds a complete, cryptographically signed `term_in` frame bound to target agent_id, timestamp, and nonce."""
    now = int(time.time())
    expires = now + max(ttl_sec, 60)
    nonce = secrets.token_hex(16)
    digest = compute_term_in_digest(
        agent_id=agent_id,
        issued_at=now,
        expires_at=expires,
        nonce=nonce,
        payload=payload,
    )
    sig = sign_term_in(
        agent_id=agent_id,
        issued_at=now,
        expires_at=expires,
        nonce=nonce,
        payload=payload,
    )
    return {
        "type": "term_in",
        "agent_id": str(agent_id),
        "issued_at": now,
        "expires_at": expires,
        "nonce": nonce,
        "payload": payload,
        "payload_sha256": digest,
        "signature": sig,
    }


def verify_task_dispatch(
    task_id: Union[UUID, str],
    command: str,
    timeout_sec: int,
    signature_b64: str,
    public_key: Optional[Union[Ed25519PublicKey, str]] = None,
    payload_sha256: Optional[str] = None,
    agent_id: Optional[Union[UUID, str]] = None,
    expected_agent_id: Optional[Union[UUID, str]] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    nonce: Optional[str] = None,
    enforce_freshness: bool = False,
) -> bool:
    """
    Verifies an Ed25519 signature, SHA-256 payload digest, recipient agent binding,
    and timestamp freshness on a C2 task/script dispatch frame.
    """
    if expected_agent_id is not None:
        if agent_id is None:
            return False
        if not secrets.compare_digest(
            str(agent_id).strip().lower(),
            str(expected_agent_id).strip().lower(),
        ):
            return False

    if enforce_freshness or (issued_at is not None and int(issued_at) != 0) or (expires_at is not None and int(expires_at) != 0):
        now = int(time.time())
        iss = int(issued_at or 0)
        exp = int(expires_at or 0)
        if iss <= 0 or exp <= 0 or exp < iss:
            return False
        if iss > now + MAX_CLOCK_SKEW_SEC or now > exp + MAX_CLOCK_SKEW_SEC:
            return False
        if not nonce or not str(nonce).strip():
            return False

    canonical = build_canonical_task_payload(
        task_id=task_id,
        command=command,
        timeout_sec=timeout_sec,
        agent_id=agent_id,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )
    if payload_sha256 is not None:
        expected_digest = compute_payload_digest(canonical)
        if not secrets.compare_digest(payload_sha256.strip().lower(), expected_digest):
            return False
    return verify_signature(canonical, signature_b64=signature_b64, public_key=public_key)
