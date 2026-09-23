package system

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// TelemetrySnapshot captures instantaneous resource metrics without external dependencies
type TelemetrySnapshot struct {
	UptimeSeconds uint64  `json:"uptime_seconds"`
	MemoryAllocMB uint64  `json:"memory_alloc_mb"`
	NumGoroutine  int     `json:"num_goroutine"`
	NumCPU        int     `json:"num_cpu"`
}

// CollectTelemetry gathers lightweight OS and runtime health metrics
func CollectTelemetry() (TelemetrySnapshot, error) {
	// 1. Gather Go runtime memory and goroutine stats
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Convert bytes to Megabytes: bytes / 1024 / 1024
	allocMB := memStats.Alloc / (1024 * 1024)

	// 2. Extract System Uptime
	uptimeSec, err := getSystemUptime()
	if err != nil {
		uptimeSec = 0
	}

	return TelemetrySnapshot{
		UptimeSeconds: uptimeSec,
		MemoryAllocMB: allocMB,
		NumGoroutine:  runtime.NumGoroutine(),
		NumCPU:        runtime.NumCPU(),
	}, nil
}

// getSystemUptime reads /proc/uptime on Linux or calculates fallback
func getSystemUptime() (uint64, error) {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/uptime")
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) > 0 {
				uptimeFloat, err := strconv.ParseFloat(fields[0], 64)
				if err == nil {
					return uint64(uptimeFloat), nil
				}
			}
		}
	}

	// Fallback for non-Linux or failed /proc reads: return 0
	return 0, fmt.Errorf("system uptime collection unsupported or unavailable")
}