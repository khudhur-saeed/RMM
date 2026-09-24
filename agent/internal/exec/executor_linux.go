//go:build linux

package exec

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// LinuxExecutor implements CommandExecutor for Linux/POSIX environments.
type LinuxExecutor struct{}

// NewExecutor returns an instance of the platform-specific executor.
func NewExecutor() CommandExecutor {
	return &LinuxExecutor{}
}

// Execute spawns a shell process under /bin/sh with process group isolation.
func (e *LinuxExecutor) Execute(ctx context.Context, command string) (CommandResult, error) {
	if command == "" {
		return CommandResult{}, ErrEmptyCommand
	}

	startTime := time.Now()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)

	// Ensure process isolation via dedicated POSIX process group
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
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
			result.ExitCode = 124 // POSIX standard timeout exit code
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