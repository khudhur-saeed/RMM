package exec

import (
	"bufio"
	"context"
	"errors"
	"os/exec"
	"time"
)

// StreamCallback represents the dispatch sink for real-time stdout/stderr chunks.
type StreamCallback func(streamType string, chunk string)

// ExecuteStreaming runs an OS-native command, streaming stdout and stderr in real time via chunks.
func ExecuteStreaming(ctx context.Context, command string, onChunk StreamCallback) (int, int64, error) {
	if command == "" {
		return -1, 0, ErrEmptyCommand
	}

	startTime := time.Now()
	cmd := prepareStreamingCmd(ctx, command)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return -1, 0, err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return -1, 0, err
	}

	if err := cmd.Start(); err != nil {
		return -1, 0, err
	}

	stdoutDone := make(chan struct{}, 1)
	stderrDone := make(chan struct{}, 1)

	// Goroutine: Live stdout pump
	go func() {
		defer func() { stdoutDone <- struct{}{} }()
		reader := bufio.NewReader(stdoutPipe)
		buf := make([]byte, 4096)
		for {
			n, readErr := reader.Read(buf)
			if n > 0 && onChunk != nil {
				onChunk("stdout", string(buf[:n]))
			}
			if readErr != nil {
				break
			}
		}
	}()

	// Goroutine: Live stderr pump
	go func() {
		defer func() { stderrDone <- struct{}{} }()
		reader := bufio.NewReader(stderrPipe)
		buf := make([]byte, 4096)
		for {
			n, readErr := reader.Read(buf)
			if n > 0 && onChunk != nil {
				onChunk("stderr", string(buf[:n]))
			}
			if readErr != nil {
				break
			}
		}
	}()

	// Barrier: Wait for pipes to be fully drained
	<-stdoutDone
	<-stderrDone

	runErr := cmd.Wait()
	elapsedMs := time.Since(startTime).Milliseconds()

	if runErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return 124, elapsedMs, ErrExecutionTimedOut
		}

		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return exitErr.ExitCode(), elapsedMs, nil
		}

		return -1, elapsedMs, runErr
	}

	return 0, elapsedMs, nil
}
