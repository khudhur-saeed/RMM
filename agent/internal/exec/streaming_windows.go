//go:build windows

package exec

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// prepareStreamingCmd configures a Windows command with suppressed console allocation.
func prepareStreamingCmd(command string) *exec.Cmd {
	cmd := buildCommand(command)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	return cmd
}

func terminateStreamingProcessTree(pid int) {
	_ = killProcessTreeWin(pid)
}
