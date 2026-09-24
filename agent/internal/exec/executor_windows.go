//go:build windows

package exec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// WindowsExecutor implements CommandExecutor for Windows environments.
type WindowsExecutor struct{}

// NewExecutor returns an instance of the platform-specific executor.
func NewExecutor() CommandExecutor {
	return &WindowsExecutor{}
}

// Execute spawns a command shell via cmd.exe suppressing console popups.
func (e *WindowsExecutor) Execute(ctx context.Context, command string) (CommandResult, error) {
	if command == "" {
		return CommandResult{}, ErrEmptyCommand
	}

	startTime := time.Now()

	cmd := exec.CommandContext(ctx, "cmd.exe", "/c", command)

	// Suppress visible console window allocation
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW,
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	runErr := cmd.Run()
	elapsed := time.Since(startTime).Milliseconds()

	result := CommandResult{
		Stdout:          stdoutBuf.String(),
		Stderr:          stderrBuf.String(),
		ExitCode:        0,
		ExecutionTimeMs: elapsed,
	}

	if runErr != nil {
		// Check if context deadline was exceeded
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			result.ExitCode = 1 // General process termination indicator
			return result, ErrExecutionTimedOut
		}

		// Extract concrete OS exit code if available
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
			return result, nil
		}

		return result, runErr
	}

	return result, nil
}