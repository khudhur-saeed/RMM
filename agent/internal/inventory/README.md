# Software Inventory Scraper

## Overview
Cross-platform installed software inventory scraper querying dpkg-query/rpm on Linux and enumerating HKLM, HKCU, and loaded HKU user registry hives on Windows.

## Interface
- ExtractInstalledSoftware() ([]SoftwareEntry, error) [software_linux.go:19, software_windows.go:67]: Enumerates installed applications across platforms
- SoftwareEntry struct [types.go:4]: Normalized application metadata with Name, Version, Publisher, and InstallDate
- SoftwareInventoryFrame struct [types.go:12]: C2 telemetry transmission frame

## Invariants
- Linux package queries filter strictly for installed status (ii prefix in dpkg) and exclude gpg-pubkey signatures in rpm [software_linux.go:69, 138]
- Windows registry scans cover HKLM (32/64-bit), HKCU, and loaded interactive user hives under HKU to discover per-user LocalAppData applications [software_windows.go:35-64, 68-82]
- Windows scraper filters out system updates (ParentKeyName), OS components (SystemComponent=1), and entries without a DisplayName [software_windows.go:137-153]
- Software entries are deduplicated by lowercase name and version key across all hives and package managers [software_linux.go:84-88, 157-161; software_windows.go:91-95]

## Side Effects
- Linux Execution: Spawns dpkg-query or rpm CLI processes with a 15-second timeout
- Windows Registry: Opens and reads registry keys across HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, and HKEY_USERS

## Verification
- Run: `cd agent && go test -v ./internal/inventory/...`
