//go:build windows

package telemetry

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	driveFixed = 3 // DRIVE_FIXED represents local hard disks and SSDs
)

var (
	procGetLogicalDriveStringsW = kernel32DLL.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = kernel32DLL.NewProc("GetDriveTypeW")
	procGetDiskFreeSpaceExW     = kernel32DLL.NewProc("GetDiskFreeSpaceExW")
)

// ReadHostDisks enumerates fixed logical drives and reads storage metrics via Win32 APIs.
func ReadHostDisks() ([]DiskPartitionStats, error) {
	// 1. Query required buffer size for logical drive strings
	r1, _, _ := procGetLogicalDriveStringsW.Call(0, 0)
	if r1 == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW failed to query buffer size")
	}

	buf := make([]uint16, r1)
	r1, _, err := procGetLogicalDriveStringsW.Call(uintptr(r1), uintptr(unsafe.Pointer(&buf[0])))
	if r1 == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW failed: %w", err)
	}

	// 2. Parse UTF-16 null-terminated strings into drive paths
	var rawDrives []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			if i > start {
				rawDrives = append(rawDrives, syscall.UTF16ToString(buf[start:i]))
			}
			start = i + 1
		}
	}

	var partitions []DiskPartitionStats

	// 3. Inspect each drive and extract metrics for DRIVE_FIXED partitions
	for _, drive := range rawDrives {
		driveUTF16, err := windows.UTF16PtrFromString(drive)
		if err != nil {
			continue
		}

		typeR1, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(driveUTF16)))
		if uint32(typeR1) != driveFixed {
			continue
		}

		var freeBytesAvailable uint64
		var totalNumberOfBytes uint64
		var totalNumberOfFreeBytes uint64

		freeR1, _, _ := procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(driveUTF16)),
			uintptr(unsafe.Pointer(&freeBytesAvailable)),
			uintptr(unsafe.Pointer(&totalNumberOfBytes)),
			uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
		)
		if freeR1 == 0 {
			continue
		}

		if totalNumberOfBytes == 0 {
			continue
		}

		usedBytes := totalNumberOfBytes - freeBytesAvailable
		usedPct := (float64(usedBytes) / float64(totalNumberOfBytes)) * 100.0

		partitions = append(partitions, DiskPartitionStats{
			MountPoint:  drive,
			Device:      drive,
			FSType:      "NTFS", // Native fixed default representation
			TotalBytes:  totalNumberOfBytes,
			FreeBytes:   freeBytesAvailable,
			UsedBytes:   usedBytes,
			UsedPercent: usedPct,
		})
	}

	return partitions, nil
}