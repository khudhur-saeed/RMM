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

// HeartbeatFrame defines the structured telemetry packet transmitted over the WebSocket tunnel
type HeartbeatFrame struct {
	Type      string `json:"type"`
	AgentID   string `json:"agent_id"`
	Timestamp int64  `json:"timestamp"`
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

	// 3. Initialize and Start Secure WebSocket Tunnel with Decoupled Routines
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

	// Launch WebSocket tunnel worker asynchronously (Reader & Writer loops)
	go wsClient.Run(ctx)

	// 4. Run Heartbeat Loop Connected to WebSocket Outbound Channel
	runHeartbeatLoop(ctx, agentCfg, wsClient)

	log.Println("[*] Tactical RMM Agent shut down gracefully.")
}

// runHeartbeatLoop dispatches periodic keep-alive telemetry into the WebSocket outbound queue
func runHeartbeatLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [Heartbeat] Context cancelled. Terminating heartbeat loop.")
			return
		case <-ticker.C:
			frame := HeartbeatFrame{
				Type:      "heartbeat",
				AgentID:   cfg.AgentID,
				Timestamp: time.Now().Unix(),
			}

			payload, err := json.Marshal(frame)
			if err != nil {
				log.Printf("[-] [Heartbeat] Failed to serialize heartbeat JSON: %v", err)
				continue
			}

			if queued := wsClient.Send(payload); queued {
				log.Printf("[+] [Heartbeat] Queued keep-alive frame for Agent [%s] (%d bytes)", cfg.AgentID, len(payload))
			} else {
				log.Printf("[-] [Heartbeat] Outbound buffer saturated; dropped frame for Agent [%s]", cfg.AgentID)
			}
		}
	}
}