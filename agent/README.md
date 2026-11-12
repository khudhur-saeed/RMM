# Go Endpoint Agent

## Overview
Tactical RMM Cross-Platform Go Endpoint Agent subsystem providing secure cryptographic enrollment, resilient C2 WebSocket tunneling, live interactive PTY terminal streaming, hardened OS command execution with process tree supervision, and comprehensive zero-dependency hardware, network, process, forensic event, and file integrity telemetry.

## Subdirectories & Boundaries
- **[cmd](./cmd/README.md)**: CLI executable entrypoints and background management daemon
- **[internal](./internal/README.md)**: Core internal agent subsystems and service drivers

## Verification
- Run: `cd agent && go test -v ./...`
