import hashlib
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse

router = APIRouter()

# Candidate directories where compiled agent binaries reside
_BINARY_SEARCH_DIRS = [
    Path("/app/bin"),
    Path(__file__).resolve().parents[5] / "agent",
    Path(__file__).resolve().parents[5] / "agent" / "build",
    Path(__file__).resolve().parents[4] / "agent",
    Path(__file__).resolve().parents[4] / "agent" / "build",
    Path("/tmp/agent_binaries"),
]


def _find_binary(filename: str) -> Path:
    for base in _BINARY_SEARCH_DIRS:
        candidate = base / filename
        if candidate.is_file() and os.access(candidate, os.R_OK):
            return candidate
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Agent binary '{filename}' is not available on this server.",
    )


@router.get(
    "/linux/{arch}",
    response_class=FileResponse,
    summary="Download compiled Linux agent binary for specified architecture",
)
async def download_linux_agent(arch: str):
    """
    Serves the pre-compiled native Linux agent executable (ELF binary).
    Used by install.sh during automated unattended endpoint bootstrap.
    """
    clean_arch = arch.lower().strip()
    if clean_arch not in ("amd64", "x86_64", "arm64", "aarch64"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported architecture: {arch}",
        )

    binary_path = _find_binary("rmmagent")
    return FileResponse(
        path=binary_path,
        media_type="application/octet-stream",
        filename="rmmagent",
    )


@router.get(
    "/windows/{arch}",
    response_class=FileResponse,
    summary="Download compiled Windows agent binary for specified architecture",
)
async def download_windows_agent(arch: str):
    """
    Serves the pre-compiled native Windows agent executable (PE32+ binary).
    Used by install.ps1 during automated unattended endpoint bootstrap.
    """
    clean_arch = arch.lower().strip()
    if clean_arch not in ("amd64", "x86_64"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported architecture: {arch}",
        )

    binary_path = _find_binary("rmmagent.exe")
    return FileResponse(
        path=binary_path,
        media_type="application/octet-stream",
        filename="rmmagent.exe",
    )


@router.get(
    "/checksums/{os_name}/{arch}",
    summary="Get SHA-256 checksum of compiled agent binary for integrity verification",
)
async def get_binary_checksum(os_name: str, arch: str):
    """
    Computes and returns the cryptographic SHA-256 digest of the requested binary
    so automated installer scripts can verify payload integrity before execution.
    """
    clean_os = os_name.lower().strip()
    clean_arch = arch.lower().strip()
    if clean_os == "linux":
        if clean_arch not in ("amd64", "x86_64", "arm64", "aarch64"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported architecture: {arch}",
            )
        bin_path = _find_binary("rmmagent")
    elif clean_os == "windows":
        if clean_arch not in ("amd64", "x86_64"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported architecture: {arch}",
            )
        bin_path = _find_binary("rmmagent.exe")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported operating system: {os_name}",
        )

    hasher = hashlib.sha256()
    with open(bin_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)

    return {
        "os": clean_os,
        "arch": clean_arch,
        "filename": bin_path.name,
        "sha256": hasher.hexdigest(),
    }
