# OS Background Service Supervisor

## Overview
Operating system background service orchestrator supporting Linux systemd unit file generation and Windows Service Control Manager (SCM Session 0) execution loops.

## Interface
- Manager interface [service.go:16]: Service lifecycle management contract (Run, Install, Uninstall, Start, Stop)
- NewManager(name, description string) Manager [service_linux.go:50, service_windows.go:25]: Returns Linux or Windows service manager instance
- ErrServiceAlreadyInstalled, ErrServiceNotInstalled, ErrUnsupportedPlatform [service.go:9-13]: Service management sentinel errors

## Invariants
- Linux service installation renders a systemd unit at /etc/systemd/system/{name}.service configured with Restart=always, RestartSec=5s, and triggers systemctl daemon-reload [service_linux.go:17-37, 75, 104]
- Windows service manager dynamically differentiates between interactive console execution and Session 0 Windows Service supervisor [service_windows.go:34-45]
- Windows SCM handler immediately transitions to svc.Running to prevent Windows Error 1053 service startup timeouts [service_windows.go:77]
- Graceful service teardown catches SIGINT/SIGTERM or SCM Stop/Shutdown commands with a 15-second deadline [service_linux.go:58-61, service_windows.go:41-43, 97-103]

## Side Effects
- Linux System: Creates /var/lib/rmmagent state directory, writes /etc/systemd/system/rmmagent.service, and executes systemctl CLI commands
- Windows API: Connects to SCM via advapi32/kernel32 (CreateService, DeleteService, StartService, ControlService)

## Verification
- Run: `cd agent && go test -v ./internal/...`
