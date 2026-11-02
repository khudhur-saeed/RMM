//go:build !windows

package inventory

// ExtractInstalledSoftware provides a cross-platform stub for non-Windows environments.
func ExtractInstalledSoftware() ([]SoftwareEntry, error) {
	return []SoftwareEntry{}, nil
}
