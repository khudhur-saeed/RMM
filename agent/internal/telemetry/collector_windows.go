//go:build windows

package telemetry

import (
	"fmt"
	"time"
)

// CollectHardwareTelemetry aggregates CPU load, host RAM breakdown, and physical disk usage on Windows.
func CollectHardwareTelemetry(agentID string) (HardwareTelemetryFrame, error) {
	// 1. Collect instantaneous CPU utilization over 300ms sampling window via GetSystemTimes
	cpuStats, err := ReadHostCPU()
	if err != nil {
		return HardwareTelemetryFrame{}, fmt.Errorf("cpu telemetry failure: %w", err)
	}

	// 2. Collect physical host RAM and pagefile capacity via GlobalMemoryStatusEx
	memStats, err := ReadHostMemory()
	if err != nil {
		return HardwareTelemetryFrame{}, fmt.Errorf("memory telemetry failure: %w", err)
	}

	// 3. Enumerate fixed drives and measure storage metrics via GetDiskFreeSpaceExW
	diskStats, err := ReadHostDisks()
	if err != nil {
		// Non-fatal defensive fallback: preserve CPU and Memory metrics even if disk query fails
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
