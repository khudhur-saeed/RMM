package telemetry

// CPUStats captures instantaneous host processor load and core layout.
type CPUStats struct {
	UsagePercent float64 `json:"usage_percent"`
	LogicalCores int     `json:"logical_cores"`
}

// MemoryStats captures host physical RAM and swap capacity in bytes.
type MemoryStats struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	UsedPercent    float64 `json:"used_percent"`
	SwapTotalBytes uint64  `json:"swap_total_bytes"`
	SwapFreeBytes  uint64  `json:"swap_free_bytes"`
}

// DiskPartitionStats represents storage metrics for a discrete filesystem mount.
type DiskPartitionStats struct {
	MountPoint  string  `json:"mount_point"`
	Device      string  `json:"device"`
	FSType      string  `json:"fs_type"`
	TotalBytes  uint64  `json:"total_bytes"`
	FreeBytes   uint64  `json:"free_bytes"`
	UsedBytes   uint64  `json:"used_bytes"`
	UsedPercent float64 `json:"used_percent"`
}

// HardwareTelemetryFrame encapsulates host resource metrics for C2 transmission.
type HardwareTelemetryFrame struct {
	Type      string               `json:"type"`
	AgentID   string               `json:"agent_id"`
	Timestamp int64                `json:"timestamp"`
	CPU       CPUStats             `json:"cpu"`
	Memory    MemoryStats          `json:"memory"`
	Disks     []DiskPartitionStats `json:"disks"`
}
