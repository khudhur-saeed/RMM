//go:build windows

package telemetry

import (
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetSystemTimes = kernel32DLL.NewProc("GetSystemTimes")
)

type cpuSystemTimes struct {
	idle   uint64
	kernel uint64
	user   uint64
}

// filetimeToUint64 converts Windows FILETIME (100-nanosecond intervals) into uint64.
func filetimeToUint64(ft windows.Filetime) uint64 {
	return (uint64(ft.HighDateTime) << 32) | uint64(ft.LowDateTime)
}

// getCPUTimes queries kernel32!GetSystemTimes and returns raw tick metrics.
func getCPUTimes() (cpuSystemTimes, error) {
	var idleTime, kernelTime, userTime windows.Filetime

	r1, _, err := procGetSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	if r1 == 0 {
		return cpuSystemTimes{}, fmt.Errorf("GetSystemTimes failed: %w", err)
	}

	return cpuSystemTimes{
		idle:   filetimeToUint64(idleTime),
		kernel: filetimeToUint64(kernelTime),
		user:   filetimeToUint64(userTime),
	}, nil
}

// ReadHostCPU calculates instantaneous CPU utilization percentage over a 300ms window on Windows.
func ReadHostCPU() (CPUStats, error) {
	t1, err := getCPUTimes()
	if err != nil {
		return CPUStats{}, err
	}

	time.Sleep(300 * time.Millisecond)

	t2, err := getCPUTimes()
	if err != nil {
		return CPUStats{}, err
	}

	deltaKernel := float64(t2.kernel - t1.kernel)
	deltaUser := float64(t2.user - t1.user)
	deltaIdle := float64(t2.idle - t1.idle)

	// In Windows, KernelTime includes IdleTime
	totalDelta := deltaKernel + deltaUser

	var usagePct float64
	if totalDelta > 0 {
		usagePct = (1.0 - (deltaIdle / totalDelta)) * 100.0
	}

	// Clamp bounds between 0.0% and 100.0%
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