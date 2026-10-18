//go:build linux

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"text/template"
	"time"
)

const systemdUnitTemplate = `[Unit]
Description={{.Description}}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart={{.BinaryPath}}
Restart=always
RestartSec=5s
WorkingDirectory=/var/lib/rmmagent
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

type unitConfig struct {
	Description string
	BinaryPath  string
}

type linuxManager struct {
	name        string
	description string
}

// NewManager returns the platform-specific Manager implementation for Linux.
func NewManager(name, description string) Manager {
	return &linuxManager{
		name:        name,
		description: description,
	}
}

func (m *linuxManager) Run(ctx context.Context, startFn func(context.Context) error) error {
	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return startFn(sigCtx)
}

func (m *linuxManager) Install() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to evaluate symlinks for executable: %w", err)
	}

	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", m.name)
	if _, err := os.Stat(unitPath); err == nil {
		return ErrServiceAlreadyInstalled
	}

	file, err := os.OpenFile(unitPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("failed to create systemd unit file (root permissions required): %w", err)
	}
	defer file.Close()

	tmpl, err := template.New("systemd").Parse(systemdUnitTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse systemd template: %w", err)
	}

	cfg := unitConfig{
		Description: m.description,
		BinaryPath:  execPath,
	}

	if err := tmpl.Execute(file, cfg); err != nil {
		return fmt.Errorf("failed to render systemd unit file: %w", err)
	}

	if err := m.runSystemctl("daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd daemon: %w", err)
	}

	if err := m.runSystemctl("enable", m.name); err != nil {
		return fmt.Errorf("failed to enable %s service: %w", m.name, err)
	}

	return nil
}

func (m *linuxManager) Uninstall() error {
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", m.name)
	if _, err := os.Stat(unitPath); os.IsNotExist(err) {
		return ErrServiceNotInstalled
	}

	_ = m.runSystemctl("stop", m.name)
	_ = m.runSystemctl("disable", m.name)

	if err := os.Remove(unitPath); err != nil {
		return fmt.Errorf("failed to remove systemd unit file: %w", err)
	}

	if err := m.runSystemctl("daemon-reload"); err != nil {
		return fmt.Errorf("failed to reload systemd daemon after removal: %w", err)
	}

	if err := m.runSystemctl("reset-failed"); err != nil {
		return fmt.Errorf("failed to reset failed systemd units: %w", err)
	}

	return nil
}

func (m *linuxManager) runSystemctl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %v failed: %w (output: %s)", args, err, string(output))
	}
	return nil
}