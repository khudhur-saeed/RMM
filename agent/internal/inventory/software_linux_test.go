//go:build !windows

package inventory

import (
	"testing"
)

func TestParseDpkgQueryOutput(t *testing.T) {
	sample := []byte(
		"ii \topenssh-server\t1:9.6p1-3ubuntu13.5\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n" +
			"rc \told-removed-pkg\t1.0.0\tDebian Maintainers\n" +
			"ii \tcurl\t8.5.0-2ubuntu10\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n" +
			"ii \tcurl\t8.5.0-2ubuntu10\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n",
	)

	entries := parseDpkgQueryOutput(sample)
	if len(entries) != 2 {
		t.Fatalf("expected 2 deduplicated installed packages, got %d", len(entries))
	}

	if entries[0].Name != "openssh-server" || entries[0].Version != "1:9.6p1-3ubuntu13.5" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].Name != "curl" {
		t.Errorf("unexpected second entry: %+v", entries[1])
	}
}

func TestParseRpmQueryOutput(t *testing.T) {
	sample := []byte(
		"bash\t5.2.26-3.fc40\tFedora Project\t1713916800\n" +
			"gpg-pubkey\t12345678-12345678\t(none)\t1713916800\n" +
			"custom-agent\t1.2.0-1.el9\t(none)\t1704067200\n",
	)

	entries := parseRpmQueryOutput(sample)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (excluding gpg-pubkey), got %d", len(entries))
	}

	if entries[0].Name != "bash" || entries[0].Publisher != "Fedora Project" || entries[0].InstallDate != "2024-04-24" {
		t.Errorf("unexpected bash rpm entry: %+v", entries[0])
	}

	if entries[1].Name != "custom-agent" || entries[1].Publisher != "" || entries[1].InstallDate != "2024-01-01" {
		t.Errorf("unexpected custom-agent rpm entry: %+v", entries[1])
	}
}

func TestExtractInstalledSoftware_LiveHost(t *testing.T) {
	entries, err := ExtractInstalledSoftware()
	if err != nil {
		t.Fatalf("expected nil error on live Linux host, got: %v", err)
	}
	t.Logf("Extracted %d installed packages from live host", len(entries))
}
