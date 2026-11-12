# Interactive Pseudoterminal (PTY) Manager

## Overview
Interactive pseudoterminal (PTY) session manager allocating native OS PTYs, spawning shell processes with xterm-256color emulation, and pumping full-duplex WebSocket frames.

## Interface
- NewSession() (*Session, error) [session.go:44]: Allocates native PTY and spawns interactive shell process (powershell.exe/cmd.exe on Windows, /bin/bash on Linux)
- (*Session) StartOutputPump(outboundChan chan<- []byte) [session.go:71]: Reads raw PTY output chunks and queues term_out JSON frames
- (*Session) WriteInput(data []byte) error [session.go:105]: Writes raw operator keystrokes into PTY stdin
- (*Session) Close() [session.go:111]: Reaps child process and closes PTY descriptor deterministically
- Session struct [session.go:17]: PTY session controller
- OutboundMessage struct [session.go:25]: JSON envelope for PTY output streaming

## Invariants
- Shell resolution selects powershell.exe (with -NoLogo) or cmd.exe on Windows, and /bin/bash (with -i) or /bin/sh on Linux [session.go:30-55]
- Environment variable TERM=xterm-256color is enforced on spawned shell processes [session.go:56]
- Session closure is idempotent (sync.Once), forcefully kills the underlying shell process, and closes PTY descriptors [session.go:112-123]

## Side Effects
- OS Processes: Allocates an OS pseudoterminal device (PTY) and spawns interactive shell child processes
- Concurrency: Spawns dedicated goroutine pumping output chunks to the outbound WebSocket channel

## Verification
- Run: `cd agent && go test -v ./internal/...`
