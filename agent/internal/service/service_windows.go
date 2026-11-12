//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type windowsManager struct {
	name        string
	description string
}

// NewManager returns the platform-specific Manager implementation for Windows.
func NewManager(name, description string) Manager {
	return &windowsManager{
		name:        name,
		description: description,
	}
}

// Run detects the execution context: interactive console vs native Windows Service.
func (m *windowsManager) Run(ctx context.Context, startFn func(context.Context) error) error {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return fmt.Errorf("failed to determine windows service execution state: %w", err)
	}

	if !isService {
		// Running interactively in a developer console / terminal
		sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, windows.SIGTERM)
		defer stop()
		return startFn(sigCtx)
	}

	// Running under Windows Service Control Manager (Session 0)
	handler := &windowsServiceHandler{
		startFn: startFn,
		rootCtx: ctx,
	}
	return svc.Run(m.name, handler)
}

type windowsServiceHandler struct {
	startFn func(context.Context) error
	rootCtx context.Context
}

// Execute fulfills the svc.Handler contract for Windows SCM event processing.
func (h *windowsServiceHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	// 1. Notify SCM that start is pending
	s <- svc.Status{State: svc.StartPending}

	serviceCtx, cancel := context.WithCancel(h.rootCtx)
	defer cancel()

	errChan := make(chan error, 1)

	// 2. Launch background agent workload asynchronously
	go func() {
		errChan <- h.startFn(serviceCtx)
	}()

	// 3. Immediately transition to Running state to avoid Error 1053 timeout
	s <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case err := <-errChan:
			// Agent runtime terminated internally
			s <- svc.Status{State: svc.StopPending}
			if err != nil && err != context.Canceled {
				return false, 1
			}
			return false, 0

		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				s <- req.CurrentStatus

			case svc.Stop, svc.Shutdown:
				// SCM requested graceful termination
				s <- svc.Status{State: svc.StopPending}
				cancel()

				// Wait for workload teardown or timeout after 15 seconds
				select {
				case <-errChan:
				case <-time.After(15 * time.Second):
				}

				return false, 0

			default:
				// Unhandled control request
			}
		}
	}
}

func (m *windowsManager) Install() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to evaluate executable symlinks: %w", err)
	}

	scManager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager (admin required): %w", err)
	}
	defer scManager.Disconnect()

	serviceHandle, err := scManager.OpenService(m.name)
	if err == nil {
		serviceHandle.Close()
		return ErrServiceAlreadyInstalled
	}

	cfg := mgr.Config{
		ServiceType:  windows.SERVICE_WIN32_OWN_PROCESS,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
		DisplayName:  m.description,
		Description:  m.description,
	}

	quotedPath := execPath
	if !strings.HasPrefix(quotedPath, "\"") {
		quotedPath = fmt.Sprintf("\"%s\"", execPath)
	}

	serviceHandle, err = scManager.CreateService(m.name, quotedPath, cfg)
	if err != nil {
		return fmt.Errorf("failed to create windows service: %w", err)
	}
	defer serviceHandle.Close()

	return nil
}

func (m *windowsManager) Uninstall() error {
	scManager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scManager.Disconnect()

	serviceHandle, err := scManager.OpenService(m.name)
	if err != nil {
		return ErrServiceNotInstalled
	}
	defer serviceHandle.Close()

	// Stop the service if it is running
	_, _ = serviceHandle.Control(svc.Stop)

	if err := serviceHandle.Delete(); err != nil {
		return fmt.Errorf("failed to mark service for deletion: %w", err)
	}

	return nil
}

func (m *windowsManager) Start() error {
	scManager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scManager.Disconnect()

	serviceHandle, err := scManager.OpenService(m.name)
	if err != nil {
		return ErrServiceNotInstalled
	}
	defer serviceHandle.Close()

	if err := serviceHandle.Start(); err != nil {
		return fmt.Errorf("failed to start windows service %s: %w", m.name, err)
	}

	return nil
}

func (m *windowsManager) Stop() error {
	scManager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to Windows Service Control Manager: %w", err)
	}
	defer scManager.Disconnect()

	serviceHandle, err := scManager.OpenService(m.name)
	if err != nil {
		return ErrServiceNotInstalled
	}
	defer serviceHandle.Close()

	if _, err := serviceHandle.Control(svc.Stop); err != nil {
		return fmt.Errorf("failed to send stop control to windows service %s: %w", m.name, err)
	}

	return nil
}
