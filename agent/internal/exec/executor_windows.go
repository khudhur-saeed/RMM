//go:build windows

package exec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxStreamCaptureBytes limits individual stdout/stderr captures to 2MB
const maxStreamCaptureBytes int64 = 2 * 1024 * 1024

// cmdDirectiveRegex matches explicit CMD invocations (e.g. "cmd /c ...", "cmd.exe /C ...", "CMD  /k ...")
// regardless of .exe extension, casing, or intermediate whitespace.
var cmdDirectiveRegex = regexp.MustCompile(`(?is)^\s*cmd(?:\.exe)?\s+(/[ck])\s+(.*)$`)

// WindowsExecutor implements CommandExecutor for Windows environments.
type WindowsExecutor struct{}

// NewExecutor returns an instance of the platform-specific executor.
func NewExecutor() CommandExecutor {
	return &WindowsExecutor{}
}

// buildCommand prepares the execution command using powershell.exe or cmd.exe
func buildCommand(command string) *exec.Cmd {
	if matches := cmdDirectiveRegex.FindStringSubmatch(command); len(matches) == 3 {
		switchFlag := strings.ToLower(matches[1])
		rawCmd := strings.TrimSpace(matches[2])
		return exec.Command("cmd.exe", switchFlag, rawCmd)
	}

	// Hardened PowerShell parameters: isolated profile, non-interactive, execution policy bypass
	return exec.Command("powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", command,
	)
}

// terminateProcessTreeWin32 walks the Windows process table via CreateToolhelp32Snapshot
// and terminates all descendant child processes (bottom-up) followed by the root PID using
// native Win32 OpenProcess + TerminateProcess calls so process termination succeeds even
// when taskkill.exe is blocked by AppLocker/WDAC or missing from PATH.
func terminateProcessTreeWin32(rootPID uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)

	childrenMap := make(map[uint32][]uint32)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	if err := windows.Process32First(snapshot, &pe); err == nil {
		for {
			if pe.ProcessID != 0 && pe.ProcessID != pe.ParentProcessID {
				childrenMap[pe.ParentProcessID] = append(childrenMap[pe.ParentProcessID], pe.ProcessID)
			}
			if err := windows.Process32Next(snapshot, &pe); err != nil {
				break
			}
		}
	}

	visited := make(map[uint32]bool)
	var orderedPIDs []uint32
	var collectDescendants func(pid uint32)
	collectDescendants = func(pid uint32) {
		if visited[pid] {
			return
		}
		visited[pid] = true
		for _, childPID := range childrenMap[pid] {
			collectDescendants(childPID)
		}
		orderedPIDs = append(orderedPIDs, pid)
	}
	collectDescendants(rootPID)

	var firstErr error
	for _, targetPID := range orderedPIDs {
		procHandle, openErr := windows.OpenProcess(windows.PROCESS_TERMINATE, false, targetPID)
		if openErr != nil {
			if targetPID == rootPID && firstErr == nil {
				firstErr = openErr
			}
			continue
		}
		if termErr := windows.TerminateProcess(procHandle, 1); termErr != nil && targetPID == rootPID && firstErr == nil {
			firstErr = termErr
		}
		_ = windows.CloseHandle(procHandle)
	}

	return firstErr
}

// killProcessTreeWin terminates the target process and all child descendants recursively
// using native Win32 APIs first, with taskkill.exe as a secondary fallback.
func killProcessTreeWin(pid int) error {
	if pid <= 0 {
		return nil
	}

	win32Err := terminateProcessTreeWin32(uint32(pid))

	killCmd := exec.Command("taskkill.exe", "/F", "/T", "/PID", strconv.Itoa(pid))
	killCmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	if taskkillErr := killCmd.Run(); taskkillErr == nil {
		return nil
	}

	return win32Err
}

// Execute runs a PowerShell script or CMD directive enforcing recursive tree termination on timeout.
func (e *WindowsExecutor) Execute(ctx context.Context, command string) (CommandResult, error) {
	if command == "" {
		return CommandResult{}, ErrEmptyCommand
	}

	startTime := time.Now()
	cmd := buildCommand(command)

	// Suppress visible console window allocation in Session 0
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

	// Goroutine dedicated to watching context cancellation and killing the entire process tree
	killDone := make(chan struct{})
	defer close(killDone)

	go func() {
		select {
		case <-ctx.Done():
			// Execute recursive tree termination via Win32 API + taskkill fallback
			if cmd.Process != nil {
				_ = killProcessTreeWin(cmd.Process.Pid)
			}
		case <-killDone:
			// Process completed normally prior to context cancellation
			return
		}
	}()

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
