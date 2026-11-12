# rmmagent CLI & Daemon Entrypoint

## Overview
Primary executable command and CLI daemon entrypoint for Tactical RMM endpoint management, supporting identity enrollment, service registration, background telemetry loops, and secure C2 WebSocket tunneling.

## Interface
- main() [main.go:57]: CLI flag parser and runtime entrypoint for enrollment, service control, and daemon loops
- serviceName string = "rmmagent" [main.go:30]: System background service identifier
- serviceDescription string [main.go:31]: Human-readable OS service description
- DefaultSigningPublicKey string [main.go:37]: Compile-time root of trust injectable via ldflags
- DefaultSigningFingerprint string [main.go:38]: Compile-time Ed25519 SHA-256 fingerprint injectable via ldflags
- HeartbeatBeaconFrame struct [main.go:42]: Periodic keep-alive beacon payload containing agent ID, unix timestamp, and system telemetry

## Invariants
- Bootstrap enrollment requires both -server URL and one-time enrollment token via CLI flag or RMM_ENROLL_TOKEN env var [main.go:96-98]
- Unauthenticated TOFU key fetch is rejected; Ed25519 public key synchronization over network requires explicit constant-time verification against a pinned SHA-256 fingerprint [main.go:252-275]
- Heartbeat loop dispatches lightweight keep-alive beacons strictly on a 30-second cadence [main.go:342]

## Side Effects
- Network: Dispatches HTTPS POST to /api/v1/enroll, HTTPS GET to /api/v1/keys/public, and establishes persistent TLS WebSocket tunnel to /api/v1/ws/agent/{agent_id}
- File System: Reads and atomically persists credentials via config.SaveConfig and config.LoadConfig
- OS Services: Interacts with OS Service Control Manager (Windows SCM or Linux systemd) to install, start, stop, or remove background service registrations
- Concurrency: Spawns concurrent background collector routines for hardware, network, process, security events, auth monitor, FIM, and software inventory

## Verification
- Run: `cd agent && go test -v ./...`
