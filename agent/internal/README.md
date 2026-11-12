# Agent Internal Subsystems

## Overview
Internal subsystem packages for the Tactical RMM agent encompassing authentication monitoring, HTTP enrollment, configuration persistence, Ed25519 cryptography, event log auditing, command execution, file integrity monitoring, software inventory, network inspection, process telemetry, OS service management, host identity, hardware telemetry, interactive PTY, and WebSocket C2 tunneling.

## Subdirectories & Boundaries
- **[authmon](./authmon/README.md)**: Linux authentication log monitor for SSH and sudo telemetry
- **[client](./client/README.md)**: HTTPS enrollment client and TLS verification
- **[config](./config/README.md)**: Agent credentials, atomic persistence, and OS permission hardening
- **[crypto](./crypto/README.md)**: Ed25519 signature verification, digest calculation, and anti-replay caching
- **[eventlog](./eventlog/README.md)**: Windows Event Log reader for Security and System channels
- **[exec](./exec/README.md)**: Cross-platform command execution, process tree termination, and streaming
- **[fim](./fim/README.md)**: File Integrity Monitoring and baseline drift detection
- **[inventory](./inventory/README.md)**: Cross-platform installed software inventory extraction
- **[netstat](./netstat/README.md)**: In-process TCP/UDP connection and socket inspector
- **[process](./process/README.md)**: In-process active process and memory enumerator
- **[service](./service/README.md)**: Native OS background service management for systemd and Windows SCM
- **[system](./system/README.md)**: Host identification, persistent hardware UUID, and runtime telemetry
- **[telemetry](./telemetry/README.md)**: Zero-dependency host hardware resource metrics (CPU, RAM, Disks)
- **[terminal](./terminal/README.md)**: Interactive pseudoterminal (PTY) session management
- **[ws](./ws/README.md)**: Full-duplex WebSocket C2 tunnel with TLS enforcement and signed dispatch

## Verification
- Run: `cd agent && go test -v ./...`
