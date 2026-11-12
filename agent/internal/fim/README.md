# File Integrity Monitor (FIM)

## Overview
File Integrity Monitoring subsystem calculating streaming SHA-256 hashes on critical system configuration paths to detect cryptographic modifications, deletions, and additions.

## Interface
- NewScanner(paths []string) *Scanner [scanner.go:43]: Initializes FIM scanner with explicit or OS-default monitored paths
- (*Scanner) InitializeBaseline() [scanner.go:56]: Captures initial cryptographic baseline without triggering alerts
- (*Scanner) ScanTargets() []FIMAlert [scanner.go:69]: Compares current filesystem state against baseline and generates drift alerts
- CalculateSHA256(filePath string) (string, error) [hasher.go:12]: Streams file contents through SHA-256 hasher without buffer allocation
- CaptureFileMetadata(filePath string) (*FileMetadata, error) [hasher.go:28]: Extracts file size, permissions, modification time, and SHA-256 hash
- BuildFIMReportFrame(agentID string, alerts []FIMAlert) FIMReportFrame [types.go:41]: Wraps integrity alerts into C2 telemetry envelope
- FIMChangeType type [types.go:6]: Enum (FIMChangeModified, FIMChangeDeleted, FIMChangeCreated)
- FileMetadata struct [types.go:15]: Baseline snapshot record
- FIMAlert struct [types.go:24]: Drift alert structure
- FIMReportFrame struct [types.go:33]: C2 telemetry envelope

## Invariants
- File hashing streams via 32KB buffers to avoid loading large files into memory [hasher.go:19-21]
- Deleted files generate FIMChangeDeleted alerts and are pruned from the baseline map [scanner.go:82-90]
- Newly created files generate FIMChangeCreated alerts and are dynamically enrolled into the baseline map [scanner.go:95-103]

## Side Effects
- File System: Sequential read-only access to monitored system files (/etc/passwd, /etc/shadow, /etc/sudoers, %SystemRoot%\System32\drivers\etc\hosts, etc.)

## Verification
- Run: `cd agent && go test -v ./internal/...`
