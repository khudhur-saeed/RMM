# Hardened Shell Executor

## Overview
Cross-platform shell command execution engine enforcing 2MB output limits, recursive process tree termination on timeout or cancellation, and live chunked stdout/stderr streaming.

## Interface
- CommandExecutor interface [executor.go:23]: Platform-agnostic execution contract
- NewExecutor() CommandExecutor [executor_linux.go:22, executor_windows.go:32]: Returns LinuxExecutor or WindowsExecutor instance
- ExecuteStreaming(ctx context.Context, command string, onChunk StreamCallback) (int, int64, error) [streaming.go:15]: Executes shell command with live stdout/stderr chunk streaming
- CommandResult struct [executor.go:15]: Output record containing Stdout, Stderr, ExitCode, and ExecutionTimeMs
- StreamCallback type [streaming.go:12]: Dispatch callback for streaming output chunks

## Invariants
- Empty command strings are rejected immediately with ErrEmptyCommand [executor.go:10, executor_linux.go:37, executor_windows.go:135]
- Stdout and stderr stream captures are strictly bounded to 2MB per stream to prevent memory exhaustion [executor_linux.go:16, executor_windows.go:22]
- Context cancellation terminates the entire process tree recursively (negative PGID SIGKILL on Linux; Toolhelp snapshot Win32 TerminateProcess with taskkill.exe fallback on Windows) [executor_linux.go:48, 74; executor_windows.go:57-110, 168-170]
- Windows PowerShell commands execute with -NoProfile -NonInteractive -ExecutionPolicy Bypass and suppress console windows via CREATE_NO_WINDOW [executor_windows.go:45-50, 143]

## Side Effects
- OS Processes: Spawns child shell processes (/bin/bash, /bin/sh, powershell.exe, cmd.exe)
- OS Signals: Sends SIGKILL signals or invokes Win32 TerminateProcess across descendant process trees

## Verification
- Run: `cd agent && go test -v ./internal/exec/...`
