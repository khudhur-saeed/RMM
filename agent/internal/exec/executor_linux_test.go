//go:build linux

package exec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLinuxExecutor_ExecutionPipeline(t *testing.T) {
	executor := NewExecutor()

	t.Run("VerifyStreamSeparation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cmd := "echo 'STANDARD_OUTPUT_STREAM'; echo 'STANDARD_ERROR_STREAM' >&2"
		res, err := executor.Execute(ctx, cmd)
		if err != nil {
			t.Fatalf("expected nil error on valid command, got: %v", err)
		}

		if res.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d", res.ExitCode)
		}

		stdoutClean := strings.TrimSpace(res.Stdout)
		stderrClean := strings.TrimSpace(res.Stderr)

		if stdoutClean != "STANDARD_OUTPUT_STREAM" {
			t.Errorf("stdout mismatch. expected 'STANDARD_OUTPUT_STREAM', got %q", stdoutClean)
		}

		if stderrClean != "STANDARD_ERROR_STREAM" {
			t.Errorf("stderr mismatch. expected 'STANDARD_ERROR_STREAM', got %q", stderrClean)
		}
	})

	t.Run("VerifyNonZeroExitCodeFidelity", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cmd := "exit 42"
		res, err := executor.Execute(ctx, cmd)
		if err != nil {
			t.Fatalf("expected nil error when process exits cleanly with code, got: %v", err)
		}

		if res.ExitCode != 42 {
			t.Errorf("expected exit code 42, got %d", res.ExitCode)
		}
	})

	t.Run("VerifyContextDeadlineExceeded", func(t *testing.T) {
		// Short timeout to force abortion
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		cmd := "sleep 3"
		res, err := executor.Execute(ctx, cmd)

		if !errors.Is(err, ErrExecutionTimedOut) {
			t.Fatalf("expected ErrExecutionTimedOut, got: %v", err)
		}

		if res.ExitCode != 124 {
			t.Errorf("expected exit code 124 for POSIX timeout, got %d", res.ExitCode)
		}
	})
}