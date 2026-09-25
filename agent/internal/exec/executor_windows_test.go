//go:build windows

package exec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWindowsExecutor_ExecutionPipeline(t *testing.T) {
	executor := NewExecutor()

	t.Run("VerifyPowerShellStreamSeparation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		// Write-Output writes to stdout, [Console]::Error.WriteLine routes directly to stderr
		cmd := "Write-Output 'POWERSHELL_STDOUT'; [Console]::Error.WriteLine('POWERSHELL_STDERR')"
		res, err := executor.Execute(ctx, cmd)
		if err != nil {
			t.Fatalf("expected nil error on valid powershell command, got: %v", err)
		}

		if res.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d", res.ExitCode)
		}

		stdoutClean := strings.TrimSpace(res.Stdout)
		stderrClean := strings.TrimSpace(res.Stderr)

		if !strings.Contains(stdoutClean, "POWERSHELL_STDOUT") {
			t.Errorf("stdout missing expected payload, got: %q", stdoutClean)
		}

		if !strings.Contains(stderrClean, "POWERSHELL_STDERR") {
			t.Errorf("stderr missing expected error payload, got: %q", stderrClean)
		}
	})

	t.Run("VerifyCmdRouting", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cmd := "cmd /c echo CMD_ROUTING_SUCCESS"
		res, err := executor.Execute(ctx, cmd)
		if err != nil {
			t.Fatalf("expected nil error on cmd execution, got: %v", err)
		}

		if res.ExitCode != 0 {
			t.Errorf("expected exit code 0, got %d", res.ExitCode)
		}

		if !strings.Contains(res.Stdout, "CMD_ROUTING_SUCCESS") {
			t.Errorf("expected 'CMD_ROUTING_SUCCESS' in stdout, got: %q", res.Stdout)
		}
	})

	t.Run("VerifyNonZeroExitCodeFidelity", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		cmd := "powershell.exe -Command exit 37"
		res, err := executor.Execute(ctx, cmd)
		if err != nil {
			t.Fatalf("expected nil error when process completes with exit code, got: %v", err)
		}

		if res.ExitCode != 37 {
			t.Errorf("expected exit code 37, got %d", res.ExitCode)
		}
	})

	t.Run("VerifyContextDeadlineExceeded", func(t *testing.T) {
		// Strict timeout enforcing process termination
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()

		cmd := "Start-Sleep -Seconds 4"
		res, err := executor.Execute(ctx, cmd)

		if !errors.Is(err, ErrExecutionTimedOut) {
			t.Fatalf("expected ErrExecutionTimedOut, got: %v", err)
		}

		if res.ExitCode != 1 {
			t.Errorf("expected exit code 1 for Windows timeout termination, got %d", res.ExitCode)
		}
	})
}