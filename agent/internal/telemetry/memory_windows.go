//go:build windows

package telemetry

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32DLL             = windows.NewLazySystemDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32DLL.NewProc("GlobalMemoryStatusEx")
)

// memoryStatusEx mirrors the Win32 MEMORYSTATUSEX struct (64 bytes).
type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

// ReadHostMemory extracts total and available physical RAM directly via GlobalMemoryStatusEx.
func ReadHostMemory() (MemoryStats, error) {
	var memStatus memoryStatusEx
	memStatus.cbSize = uint32(unsafe.Sizeof(memStatus))

	r1, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if r1 == 0 {
		return MemoryStats{}, fmt.Errorf("GlobalMemoryStatusEx failed: %w", err)
	}

	totalBytes := memStatus.ullTotalPhys
	availBytes := memStatus.ullAvailPhys
	usedBytes := totalBytes - availBytes

	var usedPct float64
	if totalBytes > 0 {
		usedPct = (float64(usedBytes) / float64(totalBytes)) * 100.0
	}

	// Pagefile metrics on Windows correspond to Swap metrics
	swapTotal := memStatus.ullTotalPageFile
	swapFree := memStatus.ullAvailPageFile

	return MemoryStats{
		TotalBytes:     totalBytes,
		AvailableBytes: availBytes,
		UsedBytes:      usedBytes,
		UsedPercent:    usedPct,
		SwapTotalBytes: swapTotal,
		SwapFreeBytes:  swapFree,
	}, nil
}