# Deployment Bootstrap Scripts

## Overview
Automated deployment bootstrap scripts for Linux and Windows endpoints, handling binary artifact retrieval, cryptographic SHA-256 verification, secure staging, endpoint enrollment, and background service lifecycle management.

## Interface
- scripts/install.sh: --server <URL> --token <TOKEN> [--ca-cert <PATH>] [--local-binary <PATH>]
- scripts/install.ps1: -ServerUrl <String> -Token <String> [-CaCertPath <String>] [-LocalBinaryPath <String>] [-InstallDir <String>]

## Invariants
- [install.sh:EUID] Execution requires root privileges (EUID 0).
- [install.sh:/run/systemd/system] Init system must be systemd.
- [install.ps1:Administrator] Execution requires elevated Administrator privileges.
- [install.sh,install.ps1:HTTPS] Control plane URL must enforce HTTPS outside local testing.
- [install.sh:ARCH] Supported Linux architectures are amd64 and arm64.
- [install.sh,install.ps1:SHA256] Downloaded binaries must match control plane SHA-256 checksum.
- [install.sh:PERMS] Linux target binary permissions are set to 0750 owned by root:root.
- [install.ps1:RMM_ENROLL_TOKEN] Enrollment token environment variable is cleared in finally block.

## Side Effects
- [install.sh:FS] Staged binary written to /usr/local/bin/rmmagent via /tmp/rmmagent_bootstrap.XXXXXXXXXX.
- [install.ps1:FS] Staged binary written to C:\Program Files\rmmagent\rmmagent.exe via $env:TEMP.
- [install.sh:SYSTEMD] Registers and starts systemd unit /etc/systemd/system/rmmagent.service.
- [install.ps1:SCM] Registers and starts Windows Service rmmagent via sc.exe and Service Control Manager.
- [install.sh,install.ps1:NET] Issues HTTPS requests for binary download, checksum validation, and agent enrollment.

## Verification
- Run: `bash -n scripts/install.sh`
