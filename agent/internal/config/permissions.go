package config

// EnforceSecureStoragePermissions enforces operating-system-specific secure access
// on the given file path (0600 on Linux, System/Admin DACLs on Windows).
func EnforceSecureStoragePermissions(path string) error {
	return enforceSecureFilePermissions(path)
}
