//go:build linux

package telemetry

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ReadHostMemory extracts physical RAM and Swap statistics directly from /proc/meminfo.
func ReadHostMemory() (MemoryStats, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemoryStats{}, fmt.Errorf("failed to open /proc/meminfo: %w", err)
	}
	defer file.Close()

	var memTotalKB, memAvailKB, swapTotalKB, swapFreeKB uint64
	var foundTotal, foundAvail bool

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := fields[0]
		valStr := fields[1]

		switch key {
		case "MemTotal:":
			if val, err := strconv.ParseUint(valStr, 10, 64); err == nil {
				memTotalKB = val
				foundTotal = true
			}
		case "MemAvailable:":
			if val, err := strconv.ParseUint(valStr, 10, 64); err == nil {
				memAvailKB = val
				foundAvail = true
			}
		case "SwapTotal:":
			if val, err := strconv.ParseUint(valStr, 10, 64); err == nil {
				swapTotalKB = val
			}
		case "SwapFree:":
			if val, err := strconv.ParseUint(valStr, 10, 64); err == nil {
				swapFreeKB = val
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return MemoryStats{}, fmt.Errorf("error reading /proc/meminfo: %w", err)
	}

	if !foundTotal || !foundAvail {
		return MemoryStats{}, fmt.Errorf("critical memory fields missing in /proc/meminfo")
	}

	totalBytes := memTotalKB * 1024
	availBytes := memAvailKB * 1024
	usedBytes := totalBytes - availBytes

	var usedPct float64
	if totalBytes > 0 {
		usedPct = (float64(usedBytes) / float64(totalBytes)) * 100.0
	}

	return MemoryStats{
		TotalBytes:     totalBytes,
		AvailableBytes: availBytes,
		UsedBytes:      usedBytes,
		UsedPercent:    usedPct,
		SwapTotalBytes: swapTotalKB * 1024,
		SwapFreeBytes:  swapFreeKB * 1024,
	}, nil
}
