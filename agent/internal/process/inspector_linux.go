//go:build linux

package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LinuxInspector implements active process discovery by scraping Linux virtual kernel interfaces.
type LinuxInspector struct {
	pageSize uint64
}

// NewInspector constructs a Linux-specific process enumerator.
func NewInspector() *LinuxInspector {
	return &LinuxInspector{
		pageSize: uint64(os.Getpagesize()),
	}
}

// GetRunningProcesses inspects /proc and parses active processes into normalized telemetry entries.
func (li *LinuxInspector) GetRunningProcesses() ([]ProcessEntry, error) {
	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	totalHostMemory := readHostTotalMemory()

	var processes []ProcessEntry

	for _, entry := range procEntries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			// Skip non-numeric virtual directories in /proc
			continue
		}

		statPath := filepath.Join("/proc", entry.Name(), "stat")
		pEntry, err := li.parseProcStat(statPath, pid, totalHostMemory)
		if err != nil {
			// Skip ephemeral processes that terminated during scanning or have access limits
			continue
		}

		processes = append(processes, pEntry)
	}

	return processes, nil
}

// parseProcStat extracts Name, PPID, and Memory RSS from /proc/[pid]/stat.
func (li *LinuxInspector) parseProcStat(statPath string, pid int, totalMem uint64) (ProcessEntry, error) {
	data, err := os.ReadFile(statPath)
	if err != nil {
		return ProcessEntry{}, err
	}

	content := string(data)

	// Comm is enclosed in parentheses: pid (comm) state ppid ...
	firstParen := strings.IndexByte(content, '(')
	lastParen := strings.LastIndexByte(content, ')')
	if firstParen == -1 || lastParen == -1 || lastParen <= firstParen {
		return ProcessEntry{}, fmt.Errorf("malformed stat entry: missing parentheses")
	}

	procName := content[firstParen+1 : lastParen]
	afterParen := strings.TrimSpace(content[lastParen+1:])
	fields := strings.Fields(afterParen)

	// fields starts immediately after comm:
	// index 0 -> state (field 3)
	// index 1 -> ppid  (field 4)
	// index 21 -> rss  (field 24)
	if len(fields) < 22 {
		return ProcessEntry{}, fmt.Errorf("insufficient fields in stat payload")
	}

	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return ProcessEntry{}, err
	}

	rssPages, err := strconv.ParseUint(fields[21], 10, 64)
	if err != nil {
		return ProcessEntry{}, err
	}

	memoryRSS := rssPages * li.pageSize

	var memoryPercent float32
	if totalMem > 0 {
		memoryPercent = float32((float64(memoryRSS) / float64(totalMem)) * 100.0)
	}

	return ProcessEntry{
		PID:           pid,
		PPID:          ppid,
		Name:          procName,
		MemoryRSS:     memoryRSS,
		MemoryPercent: memoryPercent,
	}, nil
}

// readHostTotalMemory extracts MemTotal from /proc/meminfo in bytes for percentage calculation.
func readHostTotalMemory() uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if totalKB, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					return totalKB * 1024
				}
			}
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return 0
	}

	return 0
}