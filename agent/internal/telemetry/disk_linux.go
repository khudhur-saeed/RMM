//go:build linux

package telemetry

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// ReadHostDisks scans /proc/mounts for physical block devices and measures space using syscall.Statfs.
func ReadHostDisks() ([]DiskPartitionStats, error) {
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, fmt.Errorf("failed to open /proc/mounts: %w", err)
	}
	defer file.Close()

	var partitions []DiskPartitionStats
	seenMounts := make(map[string]struct{})

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mountPoint := fields[1]
		fsType := fields[2]

		// Filter for physical block devices only (skip virtual/pseudo fs)
		if !strings.HasPrefix(device, "/dev/") {
			continue
		}

		// Avoid duplicates if a device is bind-mounted
		if _, exists := seenMounts[mountPoint]; exists {
			continue
		}
		seenMounts[mountPoint] = struct{}{}

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mountPoint, &stat); err != nil {
			continue
		}

		// If block count is 0, skip virtual/empty mounts
		if stat.Blocks == 0 {
			continue
		}

		blockSize := uint64(stat.Bsize)
		totalBytes := stat.Blocks * blockSize
		freeBytes := stat.Bavail * blockSize

		// Guard against underflow if Bavail reports more than Blocks
		var usedBytes uint64
		if totalBytes > freeBytes {
			usedBytes = totalBytes - freeBytes
		}

		var usedPct float64
		if totalBytes > 0 {
			usedPct = (float64(usedBytes) / float64(totalBytes)) * 100.0
		}

		partitions = append(partitions, DiskPartitionStats{
			MountPoint:  mountPoint,
			Device:      device,
			FSType:      fsType,
			TotalBytes:  totalBytes,
			FreeBytes:   freeBytes,
			UsedBytes:   usedBytes,
			UsedPercent: usedPct,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading /proc/mounts: %w", err)
	}

	return partitions, nil
}