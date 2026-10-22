package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"tactical-rmm/agent/internal/client"
	"tactical-rmm/agent/internal/config"
	"tactical-rmm/agent/internal/service"
	"tactical-rmm/agent/internal/system"
	"tactical-rmm/agent/internal/ws"
)

const (
	serviceName        = "rmmagent"
	serviceDescription = "Tactical RMM Endpoint Management Agent"
)

// HeartbeatBeaconFrame models the telemetry keep-alive payload dispatched upstream.
type HeartbeatBeaconFrame struct {
	Type      string                   `json:"type"`
	AgentID   string                   `json:"agent_id"`
	Timestamp int64                    `json:"timestamp"`
	Telemetry system.TelemetrySnapshot `json:"telemetry"`
}

func main() {
	var (
		serverURL     string
		token         string
		caCertPath    string
		configPath    string
		serviceAction string
		enrollOnly    bool
	)

	flag.StringVar(&serverURL, "server", "", "FastAPI Control Plane URL (e.g. https://c2.example.com)")
	flag.StringVar(&token, "token", "", "One-time enrollment bootstrap token")
	flag.StringVar(&caCertPath, "ca-cert", "", "Optional path to Custom Root CA certificate")
	flag.StringVar(&configPath, "config", "", "Optional path to local agent configuration file")
	flag.StringVar(&serviceAction, "service", "", "Service management action: [install | start | stop | uninstall]")
	flag.BoolVar(&enrollOnly, "enroll-only", false, "Perform identity bootstrap enrollment and exit immediately")
	flag.Parse()

	// 1. If explicit enrollment flag is passed, execute enrollment and exit
	if enrollOnly || (serverURL != "" && token != "" && serviceAction == "") {
		if err := bootstrapEnrollment(serverURL, token, caCertPath, configPath); err != nil {
			log.Fatalf("[-] Enrollment failure: %v", err)
		}
		log.Println("[+] Enrollment bootstrap completed successfully.")
		return
	}

	// 2. Initialize the unified native service manager
	svcMgr := service.NewManager(serviceName, serviceDescription)

	// 3. Handle standalone service lifecycle actions (install, start, stop, uninstall)
	if serviceAction != "" {
		handleServiceAction(svcMgr, serviceAction)
		return
	}

	// 4. Delegate execution lifecycle to the unified service manager
	ctx := context.Background()
	err := svcMgr.Run(ctx, func(serviceCtx context.Context) error {
		return runAgent(serviceCtx, serverURL, token, caCertPath, configPath)
	})

	if err != nil {
		log.Fatalf("[-] [Service] Lifecycle error: %v", err)
	}

	log.Println("[*] Tactical RMM Agent shut down gracefully.")
}

func handleServiceAction(mgr service.Manager, action string) {
	switch action {
	case "install":
		if err := mgr.Install(); err != nil {
			log.Fatalf("[-] Failed to install service: %v", err)
		}
		fmt.Printf("[+] Service %q installed and configured for automatic startup successfully.\n", serviceName)

	case "start":
		if err := mgr.Start(); err != nil {
			log.Fatalf("[-] Failed to start service: %v", err)
		}
		fmt.Printf("[+] Service %q started successfully.\n", serviceName)

	case "stop":
		if err := mgr.Stop(); err != nil {
			log.Fatalf("[-] Failed to stop service: %v", err)
		}
		fmt.Printf("[+] Service %q stopped successfully.\n", serviceName)

	case "uninstall":
		if err := mgr.Uninstall(); err != nil {
			log.Fatalf("[-] Failed to uninstall service: %v", err)
		}
		fmt.Printf("[+] Service %q stopped and removed from the system successfully.\n", serviceName)

	default:
		log.Fatalf("[-] Unknown service action %q. Supported actions: install, start, stop, uninstall", action)
	}
}

func bootstrapEnrollment(serverURL, token, caCertPath, configPath string) error {
	resolvedPath := config.ResolveConfigPath(configPath)

	// If existing valid config exists, log and exit cleanly
	if cfg, err := config.LoadConfig(resolvedPath); err == nil && cfg.AgentID != "" && cfg.APIKey != "" {
		log.Printf("[+] Valid existing configuration found for Agent ID [%s]. Skipping re-enrollment.", cfg.AgentID)
		return nil
	}

	hostInfo, err := system.CollectHostInfo()
	if err != nil {
		return fmt.Errorf("failed to collect host telemetry: %w", err)
	}

	log.Println("[*] Tactical RMM Agent - Initiating Endpoint Enrollment...")
	enrollClient, err := client.NewEnrollmentClient(serverURL, caCertPath, 15*time.Second)
	if err != nil {
		return fmt.Errorf("failed to initialize enrollment client: %w", err)
	}

	enrollResp, err := enrollClient.EnrollEndpoint(token, hostInfo)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	agentCfg := &config.AgentConfig{
		ServerURL:    serverURL,
		AgentID:      enrollResp.ID,
		APIKey:       enrollResp.APIKey,
		CACertPath:   caCertPath,
		HardwareUUID: hostInfo.HardwareUUID,
	}

	if err := config.SaveConfig(agentCfg, resolvedPath); err != nil {
		return fmt.Errorf("failed to securely persist credentials: %w", err)
	}
	log.Printf("[+] Enrollment Successful: Assigned Agent ID = %s", agentCfg.AgentID)
	return nil
}

func runAgent(ctx context.Context, serverURL, token, caCertPath, configPath string) error {
	resolvedConfigPath := config.ResolveConfigPath(configPath)

	agentCfg, err := config.LoadConfig(resolvedConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration at %s: %w", resolvedConfigPath, err)
	}

	log.Printf("[*] Starting Tactical RMM Agent for Agent ID [%s]...", agentCfg.AgentID)

	wsConfig := ws.Config{
		ServerURL:  agentCfg.ServerURL,
		AgentID:    agentCfg.AgentID,
		APIKey:     agentCfg.APIKey,
		CACertPath: caCertPath,
	}

	wsClient, err := ws.NewClient(wsConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize WebSocket client: %w", err)
	}

	go wsClient.Run(ctx)
	runHeartbeatLoop(ctx, agentCfg, wsClient)

	return nil
}

func runHeartbeatLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [Heartbeat] Context cancelled. Terminating heartbeat loop.")
			return
		case <-ticker.C:
			telemetry, err := system.CollectTelemetry()
			if err != nil {
				log.Printf("[-] [Heartbeat] Telemetry collection warning: %v", err)
			}

			frame := HeartbeatBeaconFrame{
				Type:      "heartbeat",
				AgentID:   cfg.AgentID,
				Timestamp: time.Now().Unix(),
				Telemetry: telemetry,
			}

			payload, err := json.Marshal(frame)
			if err != nil {
				log.Printf("[-] [Heartbeat] Failed to serialize beacon JSON: %v", err)
				continue
			}

			if queued := wsClient.Send(payload); queued {
				log.Printf("[+] [Heartbeat] Telemetry beacon queued (Mem: %dMB, Goroutines: %d, Uptime: %ds, Payload: %d bytes)",
					telemetry.MemoryAllocMB, telemetry.NumGoroutine, telemetry.UptimeSeconds, len(payload))
			} else {
				log.Printf("[-] [Heartbeat] Outbound buffer saturated; dropped telemetry frame for Agent [%s]", cfg.AgentID)
			}
		}
	}
}
