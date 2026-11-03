package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// DefaultConfigDir returns the OS-specific standard system directory for agent state.
func DefaultConfigDir() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "rmmagent")
	}
	return "/var/lib/rmmagent"
}

// ResolveConfigPath determines the active configuration file path.
// It checks: 1) Explicit path, 2) OS system path (/var/lib/rmmagent or ProgramData), 3) Executable directory fallback.
func ResolveConfigPath(explicitPath string) string {
	if explicitPath != "" {
		return explicitPath
	}

	systemCfg := filepath.Join(DefaultConfigDir(), "config.json")
	if _, err := os.Stat(systemCfg); err == nil {
		return systemCfg
	}

	if exePath, err := os.Executable(); err == nil {
		localCfg := filepath.Join(filepath.Dir(exePath), "config.json")
		if _, err := os.Stat(localCfg); err == nil {
			return localCfg
		}
	}

	return systemCfg
}

// AgentConfig represents the persistent cryptographic identity and C2 parameters.
type AgentConfig struct {
	ServerURL        string `json:"server_url"`
	AgentID          string `json:"agent_id"`
	APIKey           string `json:"api_key"`
	CACertPath       string `json:"ca_cert_path,omitempty"`
	HardwareUUID     string `json:"hardware_uuid"`
	SigningPublicKey string `json:"signing_public_key,omitempty"`
}

// utf8BOM represents the 3-byte sequence added by Windows PowerShell/Notepad.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// LoadConfig reads, strips any UTF-8 BOM, and validates the agent configuration.
func LoadConfig(path string) (*AgentConfig, error) {
	resolvedPath := ResolveConfigPath(path)

	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent config at %s: %w", resolvedPath, err)
	}

	// Strip UTF-8 BOM if present to prevent json.Unmarshal syntax failures on Windows
	data = bytes.TrimPrefix(data, utf8BOM)

	var cfg AgentConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent config: %w", err)
	}

	if cfg.AgentID == "" || cfg.APIKey == "" {
		return nil, errors.New("incomplete agent configuration: missing agent_id or api_key")
	}

	return &cfg, nil
}

// SaveConfig performs an atomic write with restricted permissions to persist credentials safely.
func SaveConfig(cfg *AgentConfig, targetPath string) error {
	resolvedPath := ResolveConfigPath(targetPath)

	targetDir := filepath.Dir(resolvedPath)
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		return fmt.Errorf("failed to create secure config directory: %w", err)
	}

	rawBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize agent config: %w", err)
	}

	// 1. Write initially to a temporary file in the same directory (ensuring same filesystem boundary)
	tmpPath := fmt.Sprintf("%s.tmp", resolvedPath)
	if err := os.WriteFile(tmpPath, rawBytes, 0600); err != nil {
		return fmt.Errorf("failed to write temporary config: %w", err)
	}

	if err := EnforceSecureStoragePermissions(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to enforce secure permissions on temporary config: %w", err)
	}

	// 2. Atomically rename temporary file over target configuration file
	if err := os.Rename(tmpPath, resolvedPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to atomically commit config: %w", err)
	}

	if err := EnforceSecureStoragePermissions(resolvedPath); err != nil {
		return fmt.Errorf("failed to enforce secure permissions on committed config: %w", err)
	}

	return nil
}
