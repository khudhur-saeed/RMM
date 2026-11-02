//go:build linux

package exec

import (
	"os/exec"
	"syscall"
)

// prepareStreamingCmd configures a POSIX shell command with an isolated process group.
func prepareStreamingCmd(command string) *exec.Cmd {
	shellPath := resolveShell()
	cmd := exec.Command(shellPath, "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd
}

func terminateStreamingProcessTree(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
