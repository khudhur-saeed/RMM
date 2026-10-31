package authmon

import "time"

// AuthEventType defines categorized authentication and privilege elevation events.
type AuthEventType string

const (
	AuthEventSSHSuccess AuthEventType = "SSH_LOGIN_SUCCESS"
	AuthEventSSHFailed  AuthEventType = "SSH_LOGIN_FAILED"
	AuthEventSudoCommand AuthEventType = "SUDO_EXECUTION"
	AuthEventSudoFailed  AuthEventType = "SUDO_FAILED"
)

// AuthEvent captures normalized forensic telemetry extracted from authentication logs.
type AuthEvent struct {
	EventType  AuthEventType `json:"event_type"`
	Timestamp  string        `json:"timestamp"`
	User       string        `json:"user"`
	SourceIP   string        `json:"source_ip,omitempty"`
	Port       int           `json:"port,omitempty"`
	Command    string        `json:"command,omitempty"`
	RawMessage string        `json:"raw_message"`
}

// AuthEventFrame aggregates authentication events for transmission over C2 tunnels.
type AuthEventFrame struct {
	Type      string      `json:"type"`
	AgentID   string      `json:"agent_id"`
	Timestamp int64       `json:"timestamp"`
	Events    []AuthEvent `json:"events"`
}

// BuildAuthEventFrame wraps parsed authentication events into a standard C2 telemetry frame.
func BuildAuthEventFrame(agentID string, events []AuthEvent) AuthEventFrame {
	if events == nil {
		events = []AuthEvent{}
	}
	return AuthEventFrame{
		Type:      "auth_telemetry",
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		Events:    events,
	}
}