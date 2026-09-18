//go:build linux

package config

import (
	"fmt"
	"os"
)

// enforceSecureFilePermissions ensures the target file has strict 0600 POSIX permissions.
func enforceSecureFilePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to inspect file metadata: %w", err)
	}

	// Verify if the current mode matches the required octal mask 0600 (-rw-------)
	if info.Mode().Perm() != 0600 {
		if err := os.Chmod(path, 0600); err != nil {
			return fmt.Errorf("failed to enforce 0600 permissions on %s: %w", path, err)
		}
	}

	return nil
}