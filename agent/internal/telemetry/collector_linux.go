//go:build linux

package telemetry

import (
	"fmt"
	"time"
)

// CollectHardwareTelemetry aggregates CPU load, host RAM breakdown, and physical disk usage.
func CollectHardwareTelemetry(agentID string) (HardwareTelemetryFrame, error) {
	// 1. Collect instantaneous CPU utilization over sample window
	cpuStats, err := ReadHostCPU()
	if err != nil {
		return HardwareTelemetryFrame{}, fmt.Errorf("cpu telemetry failure: %w", err)
	}

	// 2. Collect host memory metrics from /proc/meminfo
	memStats, err := ReadHostMemory()
	if err != nil {
		return HardwareTelemetryFrame{}, fmt.Errorf("memory telemetry failure: %w", err)
	}

	// 3. Scan physical mounts and measure space via syscall.Statfs
	diskStats, err := ReadHostDisks()
	if err != nil {
		// Non-fatal fallback: preserve CPU/Memory telemetry even if disk collection encounters errors
		diskStats = []DiskPartitionStats{}
	}

	return HardwareTelemetryFrame{
		Type:      "hardware_telemetry",
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		CPU:       cpuStats,
		Memory:    memStats,
		Disks:     diskStats,
	}, nil
}