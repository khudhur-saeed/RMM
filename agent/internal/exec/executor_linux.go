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

// maxStreamCaptureBytes limits individual stdout/stderr captures to 2MB
const maxStreamCaptureBytes int64 = 2 * 1024 * 1024

// LinuxExecutor implements CommandExecutor for Linux/POSIX environments.
type LinuxExecutor struct{}

// NewExecutor returns an instance of the platform-specific executor.
func NewExecutor() CommandExecutor {
	return &LinuxExecutor{}
}

// resolveShell selects /bin/bash if available, otherwise gracefully falls back to /bin/sh.
func resolveShell() string {
	if path, err := exec.LookPath("/bin/bash"); err == nil {
		return path
	}
	return "/bin/sh"
}

// Execute runs a command enforcing process tree termination upon context cancellation.
func (e *LinuxExecutor) Execute(ctx context.Context, command string) (CommandResult, error) {
	if command == "" {
		return CommandResult{}, ErrEmptyCommand
	}

	shellPath := resolveShell()
	startTime := time.Now()

	// Initialize command without implicit signal binding to control process group signaling
	cmd := exec.Command(shellPath, "-c", command)

	// Allocate a new POSIX process group (PGID == PID of parent process)
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

	// Goroutine dedicated to watching context cancellation and killing the entire process group
	killDone := make(chan struct{})
	defer close(killDone)

	go func() {
		select {
		case <-ctx.Done():
			// Send SIGKILL to negative PGID (-pid) to terminate root and all child descendants
			if cmd.Process != nil {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		case <-killDone:
			// Process finished normally before context cancellation
			return
		}
	}()

	// Capture streams concurrently with strict 2MB bounds
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

	// Drain output streams
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
			result.ExitCode = 124 // POSIX timeout exit code
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