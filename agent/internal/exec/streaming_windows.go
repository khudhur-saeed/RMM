//go:build windows

package exec

import (
	"context"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// prepareStreamingCmd configures a Windows command with suppressed console allocation.
func prepareStreamingCmd(ctx context.Context, command string) *exec.Cmd {
	cmd := buildCommand(command)
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	return cmd
}
