//go:build windows

package inventory

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// targetKey specifies a registry hive and root path for installed software.
type targetKey struct {
	hive registry.Key
	path string
}

// isSystemOrClassesSID returns true for non-interactive system SIDs or _Classes subkeys under HKEY_USERS.
func isSystemOrClassesSID(sid string) bool {
	trimmed := strings.TrimSpace(sid)
	upper := strings.ToUpper(trimmed)
	if trimmed == "" ||
		upper == ".DEFAULT" ||
		strings.HasSuffix(upper, "_CLASSES") ||
		upper == "S-1-5-18" ||
		upper == "S-1-5-19" ||
		upper == "S-1-5-20" {
		return true
	}
	return false
}

// enumerateUserUninstallTargets discovers per-user Uninstall registry paths across all loaded
// interactive user hives under HKEY_USERS so Windows Services running in Session 0 (LocalSystem)
// do not miss per-user applications installed under %LocalAppData%.
func enumerateUserUninstallTargets() []targetKey {
	usersKey, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer usersKey.Close()

	sids, err := usersKey.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var userTargets []targetKey
	for _, sid := range sids {
		if isSystemOrClassesSID(sid) {
			continue
		}
		userTargets = append(userTargets,
			targetKey{
				hive: registry.USERS,
				path: sid + `\Software\Microsoft\Windows\CurrentVersion\Uninstall`,
			},
			targetKey{
				hive: registry.USERS,
				path: sid + `\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
			},
		)
	}
	return userTargets
}

// ExtractInstalledSoftware scans HKLM, WOW6432Node, HKCU, and all loaded interactive user hives under HKU.
func ExtractInstalledSoftware() ([]SoftwareEntry, error) {
	targets := []targetKey{
		{
			hive: registry.LOCAL_MACHINE,
			path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
		},
		{
			hive: registry.LOCAL_MACHINE,
			path: `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		},
		{
			hive: registry.CURRENT_USER,
			path: `Software\Microsoft\Windows\CurrentVersion\Uninstall`,
		},
	}
	targets = append(targets, enumerateUserUninstallTargets()...)

	seen := make(map[string]struct{})
	var installed []SoftwareEntry

	for _, target := range targets {
		entries := scanUninstallPath(target.hive, target.path)
		for _, entry := range entries {
			// Deduplicate applications that register across multiple hives
			uniqueKey := strings.ToLower(entry.Name + "|" + entry.Version)
			if _, exists := seen[uniqueKey]; !exists {
				seen[uniqueKey] = struct{}{}
				installed = append(installed, entry)
			}
		}
	}

	return installed, nil
}

// scanUninstallPath iterates over all subkeys in a given Uninstall registry directory.
func scanUninstallPath(rootHive registry.Key, path string) []SoftwareEntry {
	key, err := registry.OpenKey(rootHive, path, registry.READ)
	if err != nil {
		return nil
	}
	defer key.Close()

	subKeyNames, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var results []SoftwareEntry

	for _, subName := range subKeyNames {
		subKeyPath := path + `\` + subName
		subKey, err := registry.OpenKey(rootHive, subKeyPath, registry.READ)
		if err != nil {
			continue
		}

		entry, valid := parseSoftwareEntry(subKey)
		subKey.Close()

		if valid {
			results = append(results, entry)
		}
	}

	return results
}

// parseSoftwareEntry applies hygiene filters and extracts application fields.
func parseSoftwareEntry(k registry.Key) (SoftwareEntry, bool) {
	// Defensive rule 1: Ignore Windows updates / patch entries
	parentKey, _, _ := k.GetStringValue("ParentKeyName")
	if parentKey != "" {
		return SoftwareEntry{}, false
	}

	// Defensive rule 2: Ignore internal operating system components
	systemComponent, _, _ := k.GetIntegerValue("SystemComponent")
	if systemComponent == 1 {
		return SoftwareEntry{}, false
	}

	// Defensive rule 3: DisplayName is mandatory
	displayName, _, err := k.GetStringValue("DisplayName")
	if err != nil || strings.TrimSpace(displayName) == "" {
		return SoftwareEntry{}, false
	}

	displayVersion, _, _ := k.GetStringValue("DisplayVersion")
	publisher, _, _ := k.GetStringValue("Publisher")
	installDate, _, _ := k.GetStringValue("InstallDate")

	return SoftwareEntry{
		Name:        strings.TrimSpace(displayName),
		Version:     strings.TrimSpace(displayVersion),
		Publisher:   strings.TrimSpace(publisher),
		InstallDate: strings.TrimSpace(installDate),
	}, true
}
