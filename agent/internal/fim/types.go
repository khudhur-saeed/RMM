package fim

import "time"

// FIMChangeType denotes the nature of the detected file system mutation.
type FIMChangeType string

const (
	FIMChangeModified FIMChangeType = "MODIFIED"
	FIMChangeDeleted  FIMChangeType = "DELETED"
	FIMChangeCreated  FIMChangeType = "CREATED"
)

// FileMetadata stores snapshot attributes and the cryptographic signature of a monitored file.
type FileMetadata struct {
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	Size        int64  `json:"size"`
	Permissions string `json:"permissions"`
	ModTime     string `json:"mod_time"`
}

// FIMAlert encapsulates an integrity deviation event between baseline and current disk state.
type FIMAlert struct {
	Path           string        `json:"path"`
	ChangeType     FIMChangeType `json:"change_type"`
	Timestamp      string        `json:"timestamp"`
	PreviousSHA256 string        `json:"previous_sha256,omitempty"`
	CurrentSHA256  string        `json:"current_sha256,omitempty"`
}

// FIMReportFrame aggregates integrity alerts for real-time dispatch over the C2 WebSocket tunnel.
type FIMReportFrame struct {
	Type      string     `json:"type"`
	AgentID   string     `json:"agent_id"`
	Timestamp int64      `json:"timestamp"`
	Alerts    []FIMAlert `json:"alerts"`
}

// BuildFIMReportFrame wraps detected integrity alerts into a standard C2 telemetry frame.
func BuildFIMReportFrame(agentID string, alerts []FIMAlert) FIMReportFrame {
	if alerts == nil {
		alerts = []FIMAlert{}
	}
	return FIMReportFrame{
		Type:      "fim_telemetry",
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		Alerts:    alerts,
	}
}
