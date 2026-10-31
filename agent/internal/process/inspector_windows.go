//go:build windows

package process

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32DLL               = windows.NewLazySystemDLL("kernel32.dll")
	procK32GetProcessMemory   = kernel32DLL.NewProc("K32GetProcessMemoryInfo")
	procGlobalMemoryStatusExW = kernel32DLL.NewProc("GlobalMemoryStatusEx")
)

const (
	processQueryLimitedInfo = 0x1000
)

// processMemoryCounters mirrors Win32 PROCESS_MEMORY_COUNTERS.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

// memoryStatusEx mirrors Win32 MEMORYSTATUSEX for host RAM calculation.
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

// WindowsInspector implements active process enumeration using Toolhelp snapshot and Win32 APIs.
type WindowsInspector struct{}

// NewInspector constructs a Windows-specific process enumerator.
func NewInspector() *WindowsInspector {
	return &WindowsInspector{}
}

// GetRunningProcesses captures a system-wide process snapshot and returns normalized telemetry entries.
func (wi *WindowsInspector) GetRunningProcesses() ([]ProcessEntry, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	totalHostRAM := getHostTotalPhysicalMemory()

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		return nil, fmt.Errorf("Process32First failed: %w", err)
	}

	var processes []ProcessEntry

	for {
		pid := int(pe.ProcessID)
		ppid := int(pe.ParentProcessID)
		name := syscall.UTF16ToString(pe.ExeFile[:])

		workingSet := getProcessWorkingSet(pe.ProcessID)

		var memoryPercent float32
		if totalHostRAM > 0 {
			memoryPercent = float32((float64(workingSet) / float64(totalHostRAM)) * 100.0)
		}

		processes = append(processes, ProcessEntry{
			PID:           pid,
			PPID:          ppid,
			Name:          name,
			MemoryRSS:     workingSet,
			MemoryPercent: memoryPercent,
		})

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}

	return processes, nil
}

// getProcessWorkingSet queries working set memory in bytes using limited query rights.
func getProcessWorkingSet(pid uint32) uint64 {
	handle, err := windows.OpenProcess(processQueryLimitedInfo, false, pid)
	if err != nil {
		// Privileged or protected processes return 0 if access is restricted
		return 0
	}
	defer windows.CloseHandle(handle)

	var counters processMemoryCounters
	counters.cb = uint32(unsafe.Sizeof(counters))

	r1, _, _ := procK32GetProcessMemory.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.cb),
	)
	if r1 == 0 {
		return 0
	}

	return uint64(counters.workingSetSize)
}

// getHostTotalPhysicalMemory reads total physical RAM via GlobalMemoryStatusEx.
func getHostTotalPhysicalMemory() uint64 {
	var memStatus memoryStatusEx
	memStatus.cbSize = uint32(unsafe.Sizeof(memStatus))

	r1, _, _ := procGlobalMemoryStatusExW.Call(uintptr(unsafe.Pointer(&memStatus)))
	if r1 == 0 {
		return 0
	}
	return memStatus.ullTotalPhys
}