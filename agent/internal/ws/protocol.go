package ws

type TaskDispatchFrame struct {
	Type       string `json:"type"`
	TaskID     string `json:"task_id"`
	Command    string `json:"command"`
	TimeoutSec int    `json:"timeout_sec"`
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