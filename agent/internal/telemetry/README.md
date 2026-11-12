# Hardware Resource Telemetry Collector

## Overview
Zero-dependency host hardware resource collector measuring CPU load over 300ms windows, RAM/swap breakdowns via /proc/meminfo or GlobalMemoryStatusEx, and physical disk partition capacities.

## Interface
- CollectHardwareTelemetry(agentID string) (HardwareTelemetryFrame, error) [collector_linux.go:11, collector_windows.go:11]: Aggregates CPU, RAM, and disk storage metrics
- ReadHostCPU() (CPUStats, error) [cpu_linux.go:61, cpu_windows.go:50]: Measures CPU utilization over a 300ms sampling window
- ReadHostMemory() (MemoryStats, error) [memory_linux.go:14, memory_windows.go:31]: Reads total, available, and used physical RAM and swap/pagefile
- ReadHostDisks() ([]DiskPartitionStats, error) [disk_linux.go:14, disk_windows.go:24]: Measures storage capacities across physical mounts / fixed drives
- CPUStats struct [types.go:4]: CPU load percentage and logical core count
- MemoryStats struct [types.go:10]: RAM and swap capacity breakdowns in bytes
- DiskPartitionStats struct [types.go:20]: Filesystem mount and partition storage metrics
- HardwareTelemetryFrame struct [types.go:30]: C2 telemetry transmission frame

## Invariants
- CPU calculation takes differential tick measurements over a 300ms window and clamps values between 0.0% and 100.0% [cpu_linux.go:67-87, cpu_windows.go:56-80]
- Disk collection filters strictly for physical devices (/dev/* on Linux; DRIVE_FIXED on Windows), ignoring virtual and pseudo filesystems [disk_linux.go:37-39, disk_windows.go:59-61]
- Disk collection errors are non-fatal and preserve CPU and memory metrics in the outgoing telemetry frame [collector_linux.go:26-29, collector_windows.go:26-29]

## Side Effects
- Linux File System: Reads /proc/stat, /proc/meminfo, /proc/mounts, and executes syscall.Statfs
- Windows API: Calls kernel32.dll (GetSystemTimes, GlobalMemoryStatusEx, GetLogicalDriveStringsW, GetDriveTypeW, GetDiskFreeSpaceExW)

## Verification
- Run: `cd agent && go test -v ./internal/...`
