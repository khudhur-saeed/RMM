package exec

import (
	"context"
	"errors"
)

// Sentinel errors for execution state boundaries
var (
	ErrEmptyCommand    = errors.New("command string cannot be empty")
	ErrExecutionTimedOut = errors.New("command execution exceeded context deadline")
)

// CommandResult encapsulates structured output across all operating systems.
type CommandResult struct {
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	ExecutionTimeMs int64  `json:"execution_time_ms"`
}

// CommandExecutor defines the platform-agnostic interface for executing shell commands.
type CommandExecutor interface {
	Execute(ctx context.Context, command string) (CommandResult, error)
}
