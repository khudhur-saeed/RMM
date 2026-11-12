package system

import (
	"runtime"
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