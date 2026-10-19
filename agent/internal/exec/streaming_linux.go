//go:build linux

package exec

import (
	"context"
	"os/exec"
	"syscall"
)

// prepareStreamingCmd configures a POSIX shell command with an isolated process group.
func prepareStreamingCmd(ctx context.Context, command string) *exec.Cmd {
	shellPath := resolveShell()
	cmd := exec.CommandContext(ctx, shellPath, "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	return cmd
}
