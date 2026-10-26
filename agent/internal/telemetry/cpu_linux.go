//go:build linux

package telemetry

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// cpuRawTimes holds cumulative CPU ticks read from /proc/stat.
type cpuRawTimes struct {
	idle  uint64
	total uint64
}

// readCPUTicks reads the first line of /proc/stat and returns (idle, total) ticks.
func readCPUTicks() (cpuRawTimes, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return cpuRawTimes{}, fmt.Errorf("failed to open /proc/stat: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return cpuRawTimes{}, fmt.Errorf("empty or unreadable /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuRawTimes{}, fmt.Errorf("invalid cpu line header in /proc/stat")
	}

	// fields: [cpu, user, nice, system, idle, iowait, irq, softirq, steal]
	var total uint64
	var idle uint64

	for idx, field := range fields[1:] {
		val, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			continue
		}
		total += val

		// fields[4] is idle, fields[5] is iowait
		if idx == 3 || idx == 4 {
			idle += val
		}
	}

	return cpuRawTimes{idle: idle, total: total}, nil
}

// ReadHostCPU calculates instantaneous CPU utilization percentage over a 300ms window.
func ReadHostCPU() (CPUStats, error) {
	t1, err := readCPUTicks()
	if err != nil {
		return CPUStats{}, err
	}

	time.Sleep(300 * time.Millisecond)

	t2, err := readCPUTicks()
	if err != nil {
		return CPUStats{}, err
	}

	deltaTotal := float64(t2.total - t1.total)
	deltaIdle := float64(t2.idle - t1.idle)

	var usagePct float64
	if deltaTotal > 0 {
		usagePct = (1.0 - (deltaIdle / deltaTotal)) * 100.0
	}

	// Clamp bounds between 0.0% and 100.0% to guard against tick anomalies
	if usagePct < 0.0 {
		usagePct = 0.0
	} else if usagePct > 100.0 {
		usagePct = 100.0
	}

	return CPUStats{
		UsagePercent: usagePct,
		LogicalCores: runtime.NumCPU(),
	}, nil
}