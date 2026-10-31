package netstat

import (
	"time"
)

// Inspector abstracts cross-platform network connection scanning.
type Inspector interface {
	GetActiveSockets() ([]SocketEntry, error)
}

// BuildSnapshot aggregates normalized sockets into an atomic telemetry frame ready for transmission.
func BuildSnapshot(agentID string, sockets []SocketEntry) NetworkSnapshotFrame {
	if sockets == nil {
		sockets = []SocketEntry{}
	}

	return NetworkSnapshotFrame{
		Type:      "network_telemetry",
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		Sockets:   sockets,
	}
}