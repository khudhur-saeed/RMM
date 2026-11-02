//go:build !windows

package inventory

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const queryTimeout = 15 * time.Second

// ExtractInstalledSoftware enumerates installed packages on Linux using dpkg-query or rpm.
func ExtractInstalledSoftware() ([]SoftwareEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()

	if dpkgPath, err := exec.LookPath("dpkg-query"); err == nil {
		return extractWithDpkgQuery(ctx, dpkgPath)
	}

	if rpmPath, err := exec.LookPath("rpm"); err == nil {
		return extractWithRpm(ctx, rpmPath)
	}

	return []SoftwareEntry{}, nil
}

// extractWithDpkgQuery queries Debian/Ubuntu package metadata via dpkg-query.
func extractWithDpkgQuery(ctx context.Context, binPath string) ([]SoftwareEntry, error) {
	cmd := exec.CommandContext(
		ctx,
		binPath,
		"-W",
		"-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Maintainer}\n",
	)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg-query execution failed: %w", err)
	}

	return parseDpkgQueryOutput(out), nil
}

// parseDpkgQueryOutput parses tab-delimited dpkg-query output and filters for installed ("ii") packages.
func parseDpkgQueryOutput(raw []byte) []SoftwareEntry {
	seen := make(map[string]struct{})
	var entries []SoftwareEntry

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}

		status := strings.TrimSpace(fields[0])
		if !strings.HasPrefix(status, "ii") {
			continue
		}

		name := strings.TrimSpace(fields[1])
		version := strings.TrimSpace(fields[2])
		if name == "" {
			continue
		}

		var publisher string
		if len(fields) >= 4 {
			publisher = strings.TrimSpace(fields[3])
		}

		uniqueKey := strings.ToLower(name + "|" + version)
		if _, exists := seen[uniqueKey]; exists {
			continue
		}
		seen[uniqueKey] = struct{}{}

		entries = append(entries, SoftwareEntry{
			Name:        name,
			Version:     version,
			Publisher:   publisher,
			InstallDate: "",
		})
	}

	return entries
}

// extractWithRpm queries RHEL/Fedora/SUSE package metadata via rpm.
func extractWithRpm(ctx context.Context, binPath string) ([]SoftwareEntry, error) {
	cmd := exec.CommandContext(
		ctx,
		binPath,
		"-qa",
		"--qf",
		"%{NAME}\t%{VERSION}-%{RELEASE}\t%{VENDOR}\t%{INSTALLTIME}\n",
	)

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rpm query execution failed: %w", err)
	}

	return parseRpmQueryOutput(out), nil
}

// parseRpmQueryOutput parses tab-delimited rpm query output and formats unix install timestamps.
func parseRpmQueryOutput(raw []byte) []SoftwareEntry {
	seen := make(map[string]struct{})
	var entries []SoftwareEntry

	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}

		name := strings.TrimSpace(fields[0])
		version := strings.TrimSpace(fields[1])
		if name == "" || strings.HasPrefix(name, "gpg-pubkey") {
			continue
		}

		var publisher string
		if len(fields) >= 3 {
			vendor := strings.TrimSpace(fields[2])
			if !strings.EqualFold(vendor, "(none)") {
				publisher = vendor
			}
		}

		var installDate string
		if len(fields) >= 4 {
			if epoch, err := strconv.ParseInt(strings.TrimSpace(fields[3]), 10, 64); err == nil && epoch > 0 {
				installDate = time.Unix(epoch, 0).UTC().Format("2006-01-02")
			}
		}

		uniqueKey := strings.ToLower(name + "|" + version)
		if _, exists := seen[uniqueKey]; exists {
			continue
		}
		seen[uniqueKey] = struct{}{}

		entries = append(entries, SoftwareEntry{
			Name:        name,
			Version:     version,
			Publisher:   publisher,
			InstallDate: installDate,
		})
	}

	return entries
}
