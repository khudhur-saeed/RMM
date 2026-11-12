# Host Identity & Runtime Telemetry

## Overview
Host identification, network interface discovery, persistent hardware UUID derivation (RFC-4122 v4 layout), and zero-dependency Go runtime telemetry collection.

## Interface
- CollectHostInfo() (*HostInfo, error) [identity.go:19]: Collects hostname, OS platform/arch, MAC addresses, private IPv4, and hardware UUID
- GetOrCreateHardwareUUID(macs []string, hostname string) string [uuid.go:20]: Resolves persistent UUID from local storage, kernel machine-id, or deterministic SHA-256 fallback
- CollectTelemetry() (TelemetrySnapshot, error) [telemetry.go:16]: Collects Go runtime memory, goroutine count, CPU count, and system uptime
- HostInfo struct [identity.go:10]: Host identification and network metadata
- TelemetrySnapshot struct [telemetry.go:8]: Instantaneous runtime health metrics

## Invariants
- Network interface collection skips loopback and inactive interfaces to extract true physical MACs and non-loopback private IPv4 [identity.go:50-73]
- Deterministic hardware UUID fallback enforces RFC-4122 version 4 (0x40) and variant bits (0x80) via SHA-256 hashing [uuid.go:68-82]
- Derived UUIDs are persisted to state storage (agent_uuid) with strict 0600 permissions [uuid.go:85-93]

## Side Effects
- File System: Reads /etc/machine-id, /sys/class/dmi/id/product_uuid, /proc/uptime, and writes agent_uuid file
- Windows API: Calls kernel32.dll (GetTickCount64) on Windows for uptime measurement

## Verification
- Run: `cd agent && go test -v ./internal/...`
