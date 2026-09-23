package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tactical-rmm/agent/internal/client"
	"tactical-rmm/agent/internal/config"
	"tactical-rmm/agent/internal/system"
	"tactical-rmm/agent/internal/ws"
)

// HeartbeatBeaconFrame models the telemetry keep-alive payload dispatched upstream
type HeartbeatBeaconFrame struct {
	Type      string                   `json:"type"`
	AgentID   string                   `json:"agent_id"`
	Timestamp int64                    `json:"timestamp"`
	Telemetry system.TelemetrySnapshot `json:"telemetry"`
}

func main() {
	var (
		serverURL  string
		token      string
		caCertPath string
		configPath string
	)

	flag.StringVar(&serverURL, "server", "", "FastAPI Control Plane URL (e.g. https://c2.example.com)")
	flag.StringVar(&token, "token", "", "One-time enrollment bootstrap token")
	flag.StringVar(&caCertPath, "ca-cert", "", "Optional path to Custom Root CA certificate")
	flag.StringVar(&configPath, "config", config.DefaultConfigFile, "Path to local agent configuration file")
	flag.Parse()

	// 1. Setup Signal Context for Graceful Daemon Shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// 2. Check for Existing Configuration (Daemon Mode vs Enrollment Mode)
	agentCfg, err := config.LoadConfig(configPath)
	if err != nil {
		if serverURL == "" || token == "" {
			log.Fatalf("[-] Configuration not found at %s. To enroll, both -server and -token are required.", configPath)
		}

		log.Println("[*] Tactical RMM Agent - Initiating Endpoint Enrollment...")
		hostInfo, err := system.CollectHostInfo()
		if err != nil {
			log.Fatalf("[-] Failed to collect host telemetry: %v", err)
		}

		enrollClient, err := client.NewEnrollmentClient(serverURL, caCertPath, 15*time.Second)
		if err != nil {
			log.Fatalf("[-] Failed to initialize enrollment client: %v", err)
		}

		enrollResp, err := enrollClient.EnrollEndpoint(token, hostInfo)
		if err != nil {
			log.Fatalf("[-] Enrollment failed: %v", err)
		}

		agentCfg = &config.AgentConfig{
			ServerURL:    serverURL,
			AgentID:      enrollResp.ID,
			APIKey:       enrollResp.APIKey,
			CACertPath:   caCertPath,
			HardwareUUID: hostInfo.HardwareUUID,
		}

		if err := config.SaveConfig(agentCfg, configPath); err != nil {
			log.Fatalf("[-] Failed to securely persist credentials: %v", err)
		}
		log.Printf("[+] Enrollment Successful: Assigned Agent ID = %s", agentCfg.AgentID)
	}

	log.Printf("[*] Starting Tactical RMM Agent Daemon for Agent ID [%s]...", agentCfg.AgentID)

	// 3. Initialize and Start Secure WebSocket Tunnel with Pong Handling
	wsConfig := ws.Config{
		ServerURL:  agentCfg.ServerURL,
		AgentID:    agentCfg.AgentID,
		APIKey:     agentCfg.APIKey,
		CACertPath: agentCfg.CACertPath,
	}

	wsClient, err := ws.NewClient(wsConfig)
	if err != nil {
		log.Fatalf("[-] Failed to initialize WebSocket client: %v", err)
	}

	// Launch WebSocket tunnel worker asynchronously
	go wsClient.Run(ctx)

	// 4. Run Heartbeat Loop Packaging Telemetry Snapshot
	runHeartbeatLoop(ctx, agentCfg, wsClient)

	log.Println("[*] Tactical RMM Agent shut down gracefully.")
}

// runHeartbeatLoop gathers snapshots and sends structured telemetry beacon frames every 30 seconds
func runHeartbeatLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [Heartbeat] Context cancelled. Terminating heartbeat loop.")
			return
		case <-ticker.C:
			// Capture instantaneous OS and runtime metrics
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