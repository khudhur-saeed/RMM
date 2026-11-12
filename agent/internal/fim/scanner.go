package fim

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// DefaultMonitoredPaths defines critical Linux authentication and privilege configurations.
var DefaultMonitoredPaths = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/ssh/sshd_config",
}

func getDefaultMonitoredPaths() []string {
	if runtime.GOOS == "windows" {
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		return []string{
			filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts"),
			filepath.Join(systemRoot, "System32", "drivers", "etc", "networks"),
			filepath.Join(systemRoot, "win.ini"),
		}
	}
	return DefaultMonitoredPaths
}

// Scanner monitors target file paths and detects cryptographic baseline drift.
type Scanner struct {
	mu          sync.RWMutex
	monitored   []string
	baselineMap map[string]FileMetadata
}

// NewScanner initializes the FIM engine with default or custom system target paths.
func NewScanner(paths []string) *Scanner {
	targetPaths := paths
	if len(targetPaths) == 0 {
		targetPaths = getDefaultMonitoredPaths()
	}

	return &Scanner{
		monitored:   targetPaths,
		baselineMap: make(map[string]FileMetadata),
	}
}

// InitializeBaseline scans all targets and persists their initial state without triggering alerts.
func (s *Scanner) InitializeBaseline() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, path := range s.monitored {
		meta, err := CaptureFileMetadata(path)
		if err == nil {
			s.baselineMap[path] = *meta
		}
	}
}

// ScanTargets inspects monitored paths against baseline and generates forensic drift alerts.
func (s *Scanner) ScanTargets() []FIMAlert {
	s.mu.Lock()
	defer s.mu.Unlock()

	var alerts []FIMAlert
	now := time.Now().UTC().Format(time.RFC3339)

	for _, path := range s.monitored {
		currentMeta, err := CaptureFileMetadata(path)
		previousMeta, existed := s.baselineMap[path]

		if err != nil {
			// Case 1: Target file was removed or deleted (unwrapping wrapped errors safely)
			if (errors.Is(err, os.ErrNotExist) || os.IsNotExist(err)) && existed {
				alerts = append(alerts, FIMAlert{
					Path:           path,
					ChangeType:     FIMChangeDeleted,
					Timestamp:      now,
					PreviousSHA256: previousMeta.SHA256,
				})
				delete(s.baselineMap, path)
			}
			continue
		}

		// Case 2: New target file created or restored
		if !existed {
			alerts = append(alerts, FIMAlert{
				Path:          path,
				ChangeType:    FIMChangeCreated,
				Timestamp:     now,
				CurrentSHA256: currentMeta.SHA256,
			})
			s.baselineMap[path] = *currentMeta
			continue
		}

		// Case 3: Content or hash mutation detected
		if currentMeta.SHA256 != previousMeta.SHA256 {
			alerts = append(alerts, FIMAlert{
				Path:           path,
				ChangeType:     FIMChangeModified,
				Timestamp:      now,
				PreviousSHA256: previousMeta.SHA256,
				CurrentSHA256:  currentMeta.SHA256,
			})
			s.baselineMap[path] = *currentMeta
		}
	}

	return alerts
}
