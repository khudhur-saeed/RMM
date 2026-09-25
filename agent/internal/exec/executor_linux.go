//go:build linux

package exec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"syscall"
	"time"
)

// maxStreamCaptureBytes limits individual stdout/stderr captures to 2MB to prevent memory exhaustion
const maxStreamCaptureBytes int64 = 2 * 1024 * 1024

// LinuxExecutor implements CommandExecutor for Linux/POSIX environments.
type LinuxExecutor struct{}

// NewExecutor returns an instance of the platform-specific executor.
func NewExecutor() CommandExecutor {
	return &LinuxExecutor{}
}

// resolveShell selects /bin/bash if available on the host, otherwise gracefully falls back to /bin/sh.
func resolveShell() string {
	if path, err := exec.LookPath("/bin/bash"); err == nil {
		return path
	}
	return "/bin/sh"
}

// Execute runs a shell command with argument isolation, stream redirection, and resource bounding.
func (e *LinuxExecutor) Execute(ctx context.Context, command string) (CommandResult, error) {
	if command == "" {
		return CommandResult{}, ErrEmptyCommand
	}

	shellPath := resolveShell()
	startTime := time.Now()

	// Argument isolation: invoke shell with -c followed explicitly by the command payload
	cmd := exec.CommandContext(ctx, shellPath, "-c", command)

	// Enforce dedicated POSIX process group to eliminate orphaned child processes
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
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
		limitedReader := io.LimitReader(stdoutPipe, maxStreamCaptureBytes)
		_, readErr := io.Copy(&stdoutBuf, limitedReader)
		stdoutDone <- readErr
	}()

	go func() {
		limitedReader := io.LimitReader(stderrPipe, maxStreamCaptureBytes)
		_, readErr := io.Copy(&stderrBuf, limitedReader)
		stderrDone <- readErr
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
			result.ExitCode = 124 // POSIX standard timeout exit code
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