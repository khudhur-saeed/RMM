# Authentication Log Monitor

## Overview
Linux authentication log monitoring subsystem tailing auth.log/secure to detect SSH logins, brute-force attempts, and sudo privilege elevations with log rotation detection.

## Interface
- NewWatcher() *Watcher [watcher.go:23]: Detects active auth log (/var/log/auth.log or /var/log/secure) and initializes incremental watcher
- (*Watcher) ReadNewEvents() ([]AuthEvent, error) [watcher.go:39]: Tails log from last known offset and parses emerging security events
- ParseAuthLine(line string) (*AuthEvent, bool) [parser.go:49]: Parses single syslog line for SSH and sudo authentication patterns
- BuildAuthEventFrame(agentID string, events []AuthEvent) AuthEventFrame [types.go:35]: Aggregates authentication events into C2 telemetry envelope
- AuthEventType type [types.go:6]: Categorized authentication event enum
- AuthEvent struct [types.go:16]: Normalized forensic event with timestamp, user, source IP, port, command, and raw message
- AuthEventFrame struct [types.go:27]: Envelope for C2 tunnel transport

## Invariants
- File offset resets to 0 if the current file size is less than previous offset to handle log rotation cleanly [watcher.go:50-52]
- Never advances offset across a partial line at EOF lacking a trailing newline [watcher.go:71-74]
- Empty or non-matching log lines are discarded without error [parser.go:50-53, 104]

## Side Effects
- File System: Read-only sequential seeking and reading of host authentication logs (/var/log/auth.log or /var/log/secure)

## Verification
- Run: `cd agent && go test -v ./internal/...`
