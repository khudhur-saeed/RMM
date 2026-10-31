//go:build !windows

package eventlog

// Watcher provides a stub implementation for non-Windows operating systems.
type Watcher struct{}

// NewWatcher initializes a stub event log watcher.
func NewWatcher() *Watcher {
	return &Watcher{}
}

// ReadSecurityEvents returns an empty event list on non-Windows hosts.
func (w *Watcher) ReadSecurityEvents(maxEvents uint32) ([]SecurityEvent, error) {
	return []SecurityEvent{}, nil
}
