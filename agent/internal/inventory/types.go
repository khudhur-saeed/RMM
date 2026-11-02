package inventory

// SoftwareEntry captures normalized metadata for an installed application across platforms.
type SoftwareEntry struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
}

// SoftwareInventoryFrame aggregates installed software for transmission across C2 tunnels.
type SoftwareInventoryFrame struct {
	Type      string          `json:"type"`
	AgentID   string          `json:"agent_id"`
	Timestamp int64           `json:"timestamp"`
	Software  []SoftwareEntry `json:"software"`
}
