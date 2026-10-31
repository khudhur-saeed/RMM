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
	"tactical-rmm/agent/internal/netstat"
	"tactical-rmm/agent/internal/process"
	"tactical-rmm/agent/internal/service"
	"tactical-rmm/agent/internal/system"
	"tactical-rmm/agent/internal/telemetry"
	"tactical-rmm/agent/internal/ws"
)

const (
	serviceName        = "rmmagent"
	serviceDescription = "Tactical RMM Endpoint Management Agent"
)

// HeartbeatBeaconFrame models the lightweight keep-alive payload dispatched upstream.
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
	flag.StringVar(&configPath, "config", "", "Optional path to local agent configuration file (defaults to auto-detected OS path)")
	flag.StringVar(&serviceAction, "service", "", "Service management action: [install | start | stop | uninstall]")
	flag.BoolVar(&enrollOnly, "enroll-only", false, "Perform identity bootstrap enrollment and exit immediately")
	flag.Parse()

	// 1. Independent bootstrap enrollment mode
	if enrollOnly || (serverURL != "" && token != "" && serviceAction == "") {
		if err := bootstrapEnrollment(serverURL, token, caCertPath, configPath); err != nil {
			log.Fatalf("[-] Enrollment failure: %v", err)
		}
		log.Println("[+] Enrollment bootstrap completed successfully.")
		return
	}

	// 2. Service lifecycle control via CLI
	svcMgr := service.NewManager(serviceName, serviceDescription)
	if serviceAction != "" {
		handleServiceAction(svcMgr, serviceAction)
		return
	}

	// 3. Daemon execution mode under OS service supervision
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

	hostInfo, err := system.CollectHostInfo()
	if err != nil {
		return fmt.Errorf("failed to collect host telemetry: %w", err)
	}
	hostInfo.HardwareUUID = system.GetOrCreateHardwareUUID(hostInfo.MACAddresses, hostInfo.Hostname)

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

	// Launch WebSocket tunnel supervisor asynchronously
	go wsClient.Run(ctx)

	// Launch Comprehensive Hardware Telemetry Loop (every 60 seconds) in background
	go runHardwareTelemetryLoop(ctx, agentCfg, wsClient)

	// Launch Network Socket Inspection Loop (every 30 seconds) in background
	go runNetworkTelemetryLoop(ctx, agentCfg, wsClient)

	// Launch Active Process Enumeration Loop (every 60 seconds) in background (Day 31)
	go runProcessTelemetryLoop(ctx, agentCfg, wsClient)

	// Run Heartbeat Loop (every 30 seconds) and block until context is cancelled
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
			telemetrySnapshot, err := system.CollectTelemetry()
			if err != nil {
				log.Printf("[-] [Heartbeat] Self-telemetry collection warning: %v", err)
			}

			frame := HeartbeatBeaconFrame{
				Type:      "heartbeat",
				AgentID:   cfg.AgentID,
				Timestamp: time.Now().Unix(),
				Telemetry: telemetrySnapshot,
			}

			payload, err := json.Marshal(frame)
			if err != nil {
				log.Printf("[-] [Heartbeat] Failed to serialize beacon JSON: %v", err)
				continue
			}

			if queued := wsClient.Send(payload); queued {
				log.Printf("[+] [Heartbeat] Lightweight beacon queued (Agent Heap: %dMB, Goroutines: %d, Uptime: %ds)",
					telemetrySnapshot.MemoryAllocMB, telemetrySnapshot.NumGoroutine, telemetrySnapshot.UptimeSeconds)
			} else {
				log.Printf("[-] [Heartbeat] Outbound buffer saturated; dropped heartbeat frame for Agent [%s]", cfg.AgentID)
			}
		}
	}
}

func runHardwareTelemetryLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [HardwareTelemetry] Context cancelled. Terminating collector loop.")
			return
		case <-ticker.C:
			frame, err := telemetry.CollectHardwareTelemetry(cfg.AgentID)
			if err != nil {
				log.Printf("[-] [HardwareTelemetry] Metric aggregation fault: %v", err)
				continue
			}

			payload, err := json.Marshal(frame)
			if err != nil {
				log.Printf("[-] [HardwareTelemetry] JSON serialization failure: %v", err)
				continue
			}

			if queued := wsClient.Send(payload); queued {
				log.Printf("[+] [HardwareTelemetry] Host metrics queued (CPU: %.2f%% [%d cores], RAM Used: %.2f%% [%dMB/%dMB], Disks: %d partitions, Payload: %d bytes)",
					frame.CPU.UsagePercent,
					frame.CPU.LogicalCores,
					frame.Memory.UsedPercent,
					frame.Memory.UsedBytes/(1024*1024),
					frame.Memory.TotalBytes/(1024*1024),
					len(frame.Disks),
					len(payload),
				)
			} else {
				log.Printf("[-] [HardwareTelemetry] Outbound buffer saturated; dropped frame for Agent [%s]", cfg.AgentID)
			}
		}
	}
}

func runNetworkTelemetryLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	inspector := netstat.NewInspector()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial immediate socket inspection on startup
	go dispatchNetworkSnapshot(cfg.AgentID, inspector, wsClient)

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [NetworkTelemetry] Context cancelled. Terminating network loop.")
			return
		case <-ticker.C:
			go dispatchNetworkSnapshot(cfg.AgentID, inspector, wsClient)
		}
	}
}

func dispatchNetworkSnapshot(agentID string, inspector netstat.Inspector, wsClient *ws.Client) {
	sockets, err := inspector.GetActiveSockets()
	if err != nil {
		log.Printf("[-] [NetworkTelemetry] Socket inspection failed: %v", err)
		return
	}

	snapshot := netstat.BuildSnapshot(agentID, sockets)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("[-] [NetworkTelemetry] Serialization failed: %v", err)
		return
	}

	if queued := wsClient.Send(payload); queued {
		log.Printf("[+] [NetworkTelemetry] Network snapshot queued (%d active sockets, Payload: %d bytes)", len(sockets), len(payload))
	} else {
		log.Printf("[-] [NetworkTelemetry] Outbound buffer saturated; dropped network frame for Agent [%s]", agentID)
	}
}

// runProcessTelemetryLoop manages the periodic active process collection loop (Day 31).
func runProcessTelemetryLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	inspector := process.NewInspector()
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Initial immediate process snapshot on startup
	go dispatchProcessSnapshot(cfg.AgentID, inspector, wsClient)

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [ProcessTelemetry] Context cancelled. Terminating process loop.")
			return
		case <-ticker.C:
			go dispatchProcessSnapshot(cfg.AgentID, inspector, wsClient)
		}
	}
}

// dispatchProcessSnapshot extracts active processes, encapsulates the telemetry frame, and queues it upstream.
func dispatchProcessSnapshot(agentID string, inspector process.Inspector, wsClient *ws.Client) {
	processes, err := inspector.GetRunningProcesses()
	if err != nil {
		log.Printf("[-] [ProcessTelemetry] Process enumeration failed: %v", err)
		return
	}

	snapshot := process.BuildSnapshot(agentID, processes)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("[-] [ProcessTelemetry] Serialization failed: %v", err)
		return
	}

	if queued := wsClient.Send(payload); queued {
		log.Printf("[+] [ProcessTelemetry] Process snapshot queued (%d active processes, Payload: %d bytes)", len(processes), len(payload))
	} else {
		log.Printf("[-] [ProcessTelemetry] Outbound buffer saturated; dropped process frame for Agent [%s]", agentID)
	}
}