package process

// ProcessEntry captures normalized telemetry for a single running OS process.
type ProcessEntry struct {
	PID           int     `json:"pid"`
	PPID          int     `json:"ppid"`
	Name          string  `json:"name"`
	MemoryRSS     uint64  `json:"memory_rss_bytes"`
	MemoryPercent float32 `json:"memory_percent"`
}

// Inspector abstracts cross-platform active process enumeration.
type Inspector interface {
	GetRunningProcesses() ([]ProcessEntry, error)
}

// ProcessSnapshotFrame aggregates process telemetry for transmission over C2 tunnels.
type ProcessSnapshotFrame struct {
	Type      string         `json:"type"`
	AgentID   string         `json:"agent_id"`
	Timestamp int64          `json:"timestamp"`
	Processes []ProcessEntry `json:"processes"`
}