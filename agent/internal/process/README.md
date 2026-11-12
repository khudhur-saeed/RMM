# Active Process Enumerator

## Overview
Active process enumerator scraping Linux /proc/[pid]/stat virtual files or invoking Windows Toolhelp32 snapshots and K32GetProcessMemoryInfo to collect PIDs, parent PIDs, names, and memory metrics.

## Interface
- Inspector interface [types.go:13]: Platform-agnostic process inspection contract
- NewInspector() *LinuxInspector / *WindowsInspector [inspector_linux.go:20, inspector_windows.go:54]: Platform inspector constructors
- BuildSnapshot(agentID string, processes []ProcessEntry) ProcessSnapshotFrame [inspector.go:8]: Wraps process entries into C2 telemetry envelope
- ProcessEntry struct [types.go:4]: Normalized process record holding PID, PPID, Name, MemoryRSS, and MemoryPercent
- ProcessSnapshotFrame struct [types.go:18]: C2 telemetry transmission frame

## Invariants
- Tolerates ephemeral processes terminating mid-scan without aborting the system-wide snapshot [inspector_linux.go:50-53, inspector_windows.go:111-113]
- Calculates process memory percentage relative to total physical host RAM extracted from /proc/meminfo or GlobalMemoryStatusEx [inspector_linux.go:102-104, 116-141; inspector_windows.go:86-88, 131-141]
- Windows inspector opens processes with PROCESS_QUERY_LIMITED_INFORMATION to gather working set sizes safely [inspector_windows.go:108-114]

## Side Effects
- Linux File System: Traverses /proc directory entries, reads /proc/[pid]/stat, and reads /proc/meminfo
- Windows API: Invokes kernel32.dll (CreateToolhelp32Snapshot, Process32First, Process32Next, OpenProcess, K32GetProcessMemoryInfo, GlobalMemoryStatusEx)

## Verification
- Run: `cd agent && go test -v ./internal/...`
