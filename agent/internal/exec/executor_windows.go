//go:build windows

package exec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// maxStreamCaptureBytes limits individual stdout/stderr captures to 2MB
const maxStreamCaptureBytes int64 = 2 * 1024 * 1024

// WindowsExecutor implements CommandExecutor for Windows environments.
type WindowsExecutor struct{}

// NewExecutor returns an instance of the platform-specific executor.
func NewExecutor() CommandExecutor {
	return &WindowsExecutor{}
}

// buildCommand prepares the execution command using powershell.exe or cmd.exe
func buildCommand(ctx context.Context, command string) *exec.Cmd {
	// If explicitly prefixed with cmd.exe, route via CMD, otherwise default to PowerShell
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(command)), "cmd /c ") {
		rawCmd := strings.TrimSpace(command)[7:]
		return exec.CommandContext(ctx, "cmd.exe", "/c", rawCmd)
	}

	// Hardened PowerShell parameters: isolated profile, non-interactive, execution policy bypass
	return exec.CommandContext(ctx, "powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", command,
	)
}

// Execute runs a PowerShell script or CMD directive suppressing console windows.
func (e *WindowsExecutor) Execute(ctx context.Context, command string) (CommandResult, error) {
	if command == "" {
		return CommandResult{}, ErrEmptyCommand
	}

	startTime := time.Now()
	cmd := buildCommand(ctx, command)

	// Suppress visible console window allocation
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW,
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return CommandResult{}, err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return CommandResult{}, err
	}

	if err := cmd.Start(); err != nil {
		return CommandResult{}, err
	}

	// Capture streams concurrently with strict size boundaries
	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutDone := make(chan error, 1)
	stderrDone := make(chan error, 1)

	go func() {
		limited := io.LimitReader(stdoutPipe, maxStreamCaptureBytes)
		_, rErr := io.Copy(&stdoutBuf, limited)
		stdoutDone <- rErr
	}()

	go func() {
		limited := io.LimitReader(stderrPipe, maxStreamCaptureBytes)
		_, rErr := io.Copy(&stderrBuf, limited)
		stderrDone <- rErr
	}()

	// Wait for stream drains to complete
	_ = <-stdoutDone
	_ = <-stderrDone

	runErr := cmd.Wait()
	elapsed := time.Since(startTime).Milliseconds()

	result := CommandResult{
		Stdout:          stdoutBuf.String(),
		Stderr:          stderrBuf.String(),
		ExitCode:        0,
		ExecutionTimeMs: elapsed,
	}

	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.ExitCode = 1 // Process termination indicator on Windows timeout
			return result, ErrExecutionTimedOut
		}

		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, nil
		}

		return result, runErr
	}

	return result, nil
}