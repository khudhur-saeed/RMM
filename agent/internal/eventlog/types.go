package eventlog

import "time"

// SecurityEvent captures normalized forensic telemetry for critical Windows security events.
type SecurityEvent struct {
	EventID          int    `json:"event_id"`
	Channel          string `json:"channel"`
	TimeCreated      string `json:"time_created"`
	ComputerName     string `json:"computer_name"`
	TargetUserName   string `json:"target_user_name,omitempty"`
	TargetDomainName string `json:"target_domain_name,omitempty"`
	LogonType        int    `json:"logon_type,omitempty"`
	IpAddress        string `json:"ip_address,omitempty"`
	ServiceName      string `json:"service_name,omitempty"`
	ImagePath        string `json:"image_path,omitempty"`
	FailureReason    string `json:"failure_reason,omitempty"`
}

// SecurityEventFrame aggregates security events for transmission across C2 WebSocket tunnels.
type SecurityEventFrame struct {
	Type      string          `json:"type"`
	AgentID   string          `json:"agent_id"`
	Timestamp int64           `json:"timestamp"`
	Events    []SecurityEvent `json:"events"`
}

// BuildSecurityEventFrame aggregates parsed security events into a unified C2 telemetry payload.
func BuildSecurityEventFrame(agentID string, events []SecurityEvent) SecurityEventFrame {
	return SecurityEventFrame{
		Type:      "security_event_telemetry",
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		Events:    events,
	}
}
