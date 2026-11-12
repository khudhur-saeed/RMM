# Agent Executables

## Overview
Executable command entrypoints for the Tactical RMM endpoint agent.

## Subdirectories & Boundaries
- **[rmmagent](./rmmagent/README.md)**: Core CLI entry point and background management daemon for endpoint enrollment, service control, and C2 communication

## Verification
- Run: `cd agent && go test -v ./...`
