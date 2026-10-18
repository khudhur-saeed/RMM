package service

import (
	"context"
	"errors"
)

// Sentinel errors for service management lifecycle boundaries.
var (
	ErrServiceAlreadyInstalled = errors.New("service is already registered in the system")
	ErrServiceNotInstalled = errors.New("service is not registered in the system")
	EttUnsupporedPlatform = errors.New("platform service manager is not supoorted")
)

// Manager defines the unified contract for OS background service orchestration.
type Manager interface {
	// Run executes the application, dynamically selecting between interactive console mode
	// and native platform daemon/SCM dispatching loops.
	Run(ctx context.Context, startFn func(context.Context) error) error

	// Install registers the compiled binary into the host OS service supervisor.
	Install() error

	// Uninstall halts execution and removes the service configuration from the system.
	Uninstall() error

}
