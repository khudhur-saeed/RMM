//go:build linux

package exec

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
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

	t.Run("VerifyProcessTreeTermination", func(t *testing.T) {
		// Unique marker to prevent collisions with other system processes
		uniqueMarker := fmt.Sprintf("rmm_leak_marker_%d", time.Now().UnixNano())

		// Strict execution budget: 200ms
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		// Command spawns an asynchronous child process in the background (&) and sleeps
		cmd := fmt.Sprintf("sh -c 'sleep 30 # %s' & sleep 30", uniqueMarker)
		_, err := executor.Execute(ctx, cmd)

		if !errors.Is(err, ErrExecutionTimedOut) {
			t.Fatalf("expected ErrExecutionTimedOut, got: %v", err)
		}

		// Grace window to let OS kernel clean up terminated process table
		time.Sleep(100 * time.Millisecond)

		// Assert zero orphaned child processes exist matching the unique marker
		checkCmd := exec.Command("pgrep", "-f", uniqueMarker)
		out, pgrepErr := checkCmd.CombinedOutput()

		// In pgrep: exit code 1 means no matching processes were found (Success state)
		if pgrepErr == nil {
			t.Fatalf("process tree termination failed: orphaned process leaked! Found PID(s):\n%s", string(out))
		}
	})
}
