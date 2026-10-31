package process

import (
	"time"
)

// BuildSnapshot wraps raw enumerated processes into an atomic, timestamped telemetry frame.
func BuildSnapshot(agentID string, processes []ProcessEntry) ProcessSnapshotFrame {
	if processes == nil {
		processes = []ProcessEntry{}
	}

	return ProcessSnapshotFrame{
		Type:      "process_telemetry",
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		Processes: processes,
	}
}
