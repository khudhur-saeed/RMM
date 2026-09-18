//go:build windows

package config

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// enforceSecureFilePermissions applies restrictive DACLs on Windows NTFS using the Win32 API.
// It assigns Full Control exclusively to NT AUTHORITY\SYSTEM and BUILTIN\Administrators,
// disabling permission inheritance from parent folders.
func enforceSecureFilePermissions(path string) error {
	// SDDL: D:P indicates a protected DACL (inheritance blocked)
	// (A;;FA;;;SY) -> Allow Full Access to SYSTEM
	// (A;;FA;;;BA) -> Allow Full Access to Builtin Administrators
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

	secDesc, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("failed to generate DACL descriptor from SDDL: %w", err)
	}

	daclPtr, _, err := secDesc.DACL()
	if err != nil {
		return fmt.Errorf("failed to retrieve DACL pointer: %w", err)
	}

	// Explicit type casting to windows.SECURITY_INFORMATION to satisfy strict Win32 type definitions
	securityFlags := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)

	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		securityFlags,
		nil,
		nil,
		daclPtr,
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to set restrictive security info via Win32: %w", err)
	}

	return nil
}
