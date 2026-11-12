# Windows Event Log Auditor

## Overview
Windows Event Log monitor querying critical Security (4624, 4625) and System (7045) events via native Win32 wevtapi.dll with in-memory deduplication, with no-op stub on non-Windows platforms.

## Interface
- NewWatcher() *Watcher [watcher_windows.go:59, watcher_other.go:9]: Initializes platform-appropriate event log watcher
- (*Watcher) ReadSecurityEvents(maxEvents uint32) ([]SecurityEvent, error) [watcher_windows.go:67, watcher_other.go:14]: Queries and deduplicates security and system events
- BuildSecurityEventFrame(agentID string, events []SecurityEvent) SecurityEventFrame [types.go:29]: Wraps events into C2 telemetry frame
- SecurityEvent struct [types.go:6]: Normalized forensic event with EventID, Channel, TimeCreated, TargetUserName, LogonType, and ServiceName
- SecurityEventFrame struct [types.go:21]: Envelope for C2 WebSocket transport

## Invariants
- Non-Windows operating systems return an empty event slice without error [watcher_other.go:15]
- In-memory deduplication cache resets to active events once reaching 10,000 entries to prevent memory exhaustion [watcher_windows.go:100-106]
- Two-pass buffer sizing pattern is enforced for Win32 EvtRender to allocate exact UTF-16 memory buffers [watcher_windows.go:173-199]

## Side Effects
- Windows API: Calls wevtapi.dll (EvtQuery, EvtNext, EvtRender, EvtClose) to query Security and System event logs
- Memory: Maintains synchronized event key deduplication cache

## Verification
- Run: `cd agent && go test -v ./internal/...`
