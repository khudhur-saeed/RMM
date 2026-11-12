package ws

type TaskDispatchFrame struct {
	Type          string `json:"type"`
	TaskID        string `json:"task_id"`
	AgentID       string `json:"agent_id,omitempty"`
	IssuedAt      int64  `json:"issued_at,omitempty"`
	ExpiresAt     int64  `json:"expires_at,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	Command       string `json:"command"`
	TimeoutSec    int    `json:"timeout_sec"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

type TermInFrame struct {
	Type          string `json:"type"`
	AgentID       string `json:"agent_id,omitempty"`
	IssuedAt      int64  `json:"issued_at,omitempty"`
	ExpiresAt     int64  `json:"expires_at,omitempty"`
	Nonce         string `json:"nonce,omitempty"`
	Payload       string `json:"payload"`
	PayloadSHA256 string `json:"payload_sha256,omitempty"`
	Signature     string `json:"signature,omitempty"`
}

type TaskStreamFrame struct {
	Type   string `json:"type"`
	TaskID string `json:"task_id"`
	Stream string `json:"stream"` // "stdout" أو "stderr"
	Chunk  string `json:"chunk"`
}

type TaskExitFrame struct {
	Type      string  `json:"type"`
	TaskID    string  `json:"task_id"`
	ExitCode  int     `json:"exit_code"`
	ElapsedMs int64   `json:"elapsed_ms"`
	Error     *string `json:"error,omitempty"`
}
