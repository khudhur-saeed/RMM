package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultConfigDir  = "/var/lib/rmmagent"
	DefaultConfigFile = "/var/lib/rmmagent/config.json"
)

// AgentConfig encapsulates permanent identity, API credentials, and network targeting
type AgentConfig struct {
	ServerURL    string `json:"server_url"`
	AgentID      string `json:"agent_id"`
	APIKey       string `json:"api_key"`
	CACertPath   string `json:"ca_cert_path,omitempty"`
	HardwareUUID string `json:"hardware_uuid"`
}

// LoadConfig reads and parses the hardened configuration file from disk
func LoadConfig(path string) (*AgentConfig, error) {
	if path == "" {
		path = DefaultConfigFile
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent config: %w", err)
	}

	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent config: %w", err)
	}

	if cfg.AgentID == "" || cfg.APIKey == "" {
		return nil, errors.New("incomplete agent configuration: missing agent_id or api_key")
	}

	return &cfg, nil
}

// SaveConfig performs an atomic write with 0600 permissions to persist credentials
func SaveConfig(cfg *AgentConfig, targetPath string) error {
	if targetPath == "" {
		targetPath = DefaultConfigFile
	}

	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("failed to create secure config directory: %w", err)
	}

	rawBytes, err := json.MarshalIndent(cfg, "", "	")
	if err != nil {
		return fmt.Errorf("failed to serialize agent config: %w", err)
	}

	// 1. Write initially to a temporary file in the same directory (ensuring same filesystem boundary)
	tmpPath := fmt.Sprintf("%s.tmp", targetPath)
	if err := os.WriteFile(tmpPath, rawBytes, 0600); err != nil {
		return fmt.Errorf("failed to write temporary config: %w", err)
	}

	// 2. Atomically rename temporary file over target configuration file
	if err := os.Rename(tmpPath, targetPath); err != nil {
		// Clean up temporary artifact on failure
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to atomically commit config: %w", err)
	}

	return nil
}
