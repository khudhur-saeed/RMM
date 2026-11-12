package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"tactical-rmm/agent/internal/authmon"
	"tactical-rmm/agent/internal/client"
	"tactical-rmm/agent/internal/config"
	agentCrypto "tactical-rmm/agent/internal/crypto"
	"tactical-rmm/agent/internal/eventlog"
	"tactical-rmm/agent/internal/fim"
	"tactical-rmm/agent/internal/inventory"
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

// Compile-time cryptographic root of trust injectable via -ldflags:
// -ldflags "-X main.DefaultSigningPublicKey=... -X main.DefaultSigningFingerprint=..."
var (
	DefaultSigningPublicKey   = ""
	DefaultSigningFingerprint = ""
)

// HeartbeatBeaconFrame models the lightweight keep-alive payload dispatched upstream.
type HeartbeatBeaconFrame struct {
	Type      string                   `json:"type"`
	AgentID   string                   `json:"agent_id"`
	Timestamp int64                    `json:"timestamp"`
	Telemetry system.TelemetrySnapshot `json:"telemetry"`
}

type cliSecurityOptions struct {
	SigningPubKey      string
	SigningFingerprint string
	CertPinSHA256      string
	ClientCertPath     string
	ClientKeyPath      string
}

func main() {
	var (
		serverURL     string
		token         string
		caCertPath    string
		configPath    string
		serviceAction string
		enrollOnly    bool
		secOpts       cliSecurityOptions
	)

	flag.StringVar(&serverURL, "server", "", "FastAPI Control Plane URL (e.g. https://c2.example.com)")
	flag.StringVar(&token, "token", "", "One-time enrollment bootstrap token")
	flag.StringVar(&caCertPath, "ca-cert", "", "Optional path to Custom Root CA certificate")
	flag.StringVar(&configPath, "config", "", "Optional path to local agent configuration file")
	flag.StringVar(&serviceAction, "service", "", "Service management action: [install | start | stop | uninstall]")
	flag.BoolVar(&enrollOnly, "enroll-only", false, "Perform identity bootstrap enrollment and exit immediately")
	flag.StringVar(&secOpts.SigningPubKey, "signing-pubkey", DefaultSigningPublicKey, "Pinned Base64 or PEM Ed25519 verification public key")
	flag.StringVar(&secOpts.SigningFingerprint, "signing-pubkey-fingerprint", DefaultSigningFingerprint, "Pinned SHA-256 hex fingerprint of the server Ed25519 public key")
	flag.StringVar(&secOpts.CertPinSHA256, "cert-pin-sha256", "", "Pinned SHA-256 hex digest of the server TLS certificate or SPKI")
	flag.StringVar(&secOpts.ClientCertPath, "client-cert", "", "Optional path to mTLS client certificate PEM")
	flag.StringVar(&secOpts.ClientKeyPath, "client-key", "", "Optional path to mTLS client private key PEM")
	flag.Parse()

	if token == "" {
		token = strings.TrimSpace(os.Getenv("RMM_ENROLL_TOKEN"))
	}
	if secOpts.SigningPubKey == "" {
		secOpts.SigningPubKey = strings.TrimSpace(os.Getenv("RMM_SIGNING_PUBKEY"))
	}
	if secOpts.SigningFingerprint == "" {
		secOpts.SigningFingerprint = strings.TrimSpace(os.Getenv("RMM_SIGNING_PUBKEY_FINGERPRINT"))
	}
	if secOpts.CertPinSHA256 == "" {
		secOpts.CertPinSHA256 = strings.TrimSpace(os.Getenv("RMM_CERT_PIN_SHA256"))
	}

	// 1. Independent bootstrap enrollment mode
	if enrollOnly || (serverURL != "" && token != "" && serviceAction == "") {
		if serverURL == "" || token == "" {
			log.Fatalf("[-] Enrollment requires both -server and -token (or RMM_ENROLL_TOKEN)")
		}
		if err := bootstrapEnrollment(serverURL, token, caCertPath, configPath, secOpts); err != nil {
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
		return runAgent(serviceCtx, serverURL, token, caCertPath, configPath, secOpts)
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

func bootstrapEnrollment(serverURL, token, caCertPath, configPath string, secOpts cliSecurityOptions) error {
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
	if err := enrollClient.ConfigureTLS(secOpts.ClientCertPath, secOpts.ClientKeyPath, secOpts.CertPinSHA256); err != nil {
		return fmt.Errorf("failed to configure enrollment TLS security controls: %w", err)
	}

	enrollResp, err := enrollClient.EnrollEndpoint(token, hostInfo)
	if err != nil {
		return fmt.Errorf("enrollment failed: %w", err)
	}

	effectivePubKey := strings.TrimSpace(secOpts.SigningPubKey)
	if effectivePubKey == "" {
		effectivePubKey = strings.TrimSpace(enrollResp.SigningPublicKey)
	}

	var computedFingerprint string
	if effectivePubKey != "" {
		parsedKey, parseErr := agentCrypto.ParseEd25519PublicKey(effectivePubKey)
		if parseErr != nil {
			return fmt.Errorf("invalid Ed25519 public key received during enrollment: %w", parseErr)
		}
		computedFingerprint = agentCrypto.ComputePublicKeyFingerprint(parsedKey)
		if strings.TrimSpace(secOpts.SigningFingerprint) != "" {
			if fpErr := agentCrypto.VerifyPublicKeyFingerprint(effectivePubKey, secOpts.SigningFingerprint); fpErr != nil {
				return fmt.Errorf("enrollment aborted due to Ed25519 public key pin violation: %w", fpErr)
			}
		}
	}

	agentCfg := &config.AgentConfig{
		ServerURL:            serverURL,
		AgentID:              enrollResp.ID,
		APIKey:               enrollResp.APIKey,
		CACertPath:           caCertPath,
		ClientCertPath:       secOpts.ClientCertPath,
		ClientKeyPath:        secOpts.ClientKeyPath,
		ServerCertPinSHA256:  secOpts.CertPinSHA256,
		HardwareUUID:         hostInfo.HardwareUUID,
		SigningPublicKey:     effectivePubKey,
		SigningKeyFingerprint: computedFingerprint,
	}

	if err := config.SaveConfig(agentCfg, resolvedPath); err != nil {
		return fmt.Errorf("failed to securely persist credentials: %w", err)
	}
	log.Printf("[+] Enrollment Successful: Assigned Agent ID = %s", agentCfg.AgentID)
	return nil
}

func runAgent(ctx context.Context, serverURL, token, caCertPath, configPath string, secOpts cliSecurityOptions) error {
	resolvedConfigPath := config.ResolveConfigPath(configPath)

	agentCfg, err := config.LoadConfig(resolvedConfigPath)
	if err != nil {
		return fmt.Errorf("failed to load configuration at %s: %w", resolvedConfigPath, err)
	}

	log.Printf("[*] Starting Tactical RMM Agent for Agent ID [%s]...", agentCfg.AgentID)

	effectiveCACert := agentCfg.CACertPath
	if caCertPath != "" {
		effectiveCACert = caCertPath
	}

	effectiveClientCert := agentCfg.ClientCertPath
	if secOpts.ClientCertPath != "" {
		effectiveClientCert = secOpts.ClientCertPath
	}
	effectiveClientKey := agentCfg.ClientKeyPath
	if secOpts.ClientKeyPath != "" {
		effectiveClientKey = secOpts.ClientKeyPath
	}
	effectiveCertPin := agentCfg.ServerCertPinSHA256
	if secOpts.CertPinSHA256 != "" {
		effectiveCertPin = secOpts.CertPinSHA256
	}

	if strings.TrimSpace(agentCfg.SigningPublicKey) == "" && strings.TrimSpace(secOpts.SigningPubKey) != "" {
		agentCfg.SigningPublicKey = strings.TrimSpace(secOpts.SigningPubKey)
	}

	expectedFingerprint := strings.TrimSpace(secOpts.SigningFingerprint)
	if expectedFingerprint == "" {
		expectedFingerprint = strings.TrimSpace(agentCfg.SigningKeyFingerprint)
	}

	// Eliminate unauthenticated TOFU: only synchronize public key over network if an explicit
	// SHA-256 fingerprint pin is configured and verified in constant time.
	if strings.TrimSpace(agentCfg.SigningPublicKey) == "" {
		if expectedFingerprint == "" {
			log.Println("[!] [Security] No pinned Ed25519 verification key or SHA-256 fingerprint configured; refusing unverified TOFU key fetch.")
		} else if enrollClient, err := client.NewEnrollmentClient(agentCfg.ServerURL, effectiveCACert, 10*time.Second); err == nil {
			if tlsErr := enrollClient.ConfigureTLS(effectiveClientCert, effectiveClientKey, effectiveCertPin); tlsErr != nil {
				return fmt.Errorf("failed to configure TLS for key synchronization: %w", tlsErr)
			}
			if pubResp, fetchErr := enrollClient.FetchServerPublicKey(); fetchErr == nil && pubResp.PublicKeyB64 != "" {
				if fpErr := agentCrypto.VerifyPublicKeyFingerprint(pubResp.PublicKeyB64, expectedFingerprint); fpErr != nil {
					return fmt.Errorf("rejected server Ed25519 public key due to fingerprint mismatch: %w", fpErr)
				}
				agentCfg.SigningPublicKey = pubResp.PublicKeyB64
				agentCfg.SigningKeyFingerprint = expectedFingerprint
				_ = config.SaveConfig(agentCfg, resolvedConfigPath)
				log.Printf("[+] [Security] Verified and synchronized Ed25519 public key against pinned fingerprint (SHA256: %s)", expectedFingerprint)
			}
		}
	} else if expectedFingerprint != "" {
		if fpErr := agentCrypto.VerifyPublicKeyFingerprint(agentCfg.SigningPublicKey, expectedFingerprint); fpErr != nil {
			return fmt.Errorf("stored Ed25519 public key does not match pinned SHA-256 fingerprint: %w", fpErr)
		}
	}

	wsConfig := ws.Config{
		ServerURL:           agentCfg.ServerURL,
		AgentID:             agentCfg.AgentID,
		APIKey:              agentCfg.APIKey,
		CACertPath:          effectiveCACert,
		ClientCertPath:      effectiveClientCert,
		ClientKeyPath:       effectiveClientKey,
		ServerCertPinSHA256: effectiveCertPin,
		SigningPublicKey:    agentCfg.SigningPublicKey,
	}

	wsClient, err := ws.NewClient(wsConfig)
	if err != nil {
		return fmt.Errorf("failed to initialize WebSocket client: %w", err)
	}

	var wg sync.WaitGroup

	// 1. Launch WebSocket tunnel supervisor asynchronously and track lifecycle
	wg.Add(1)
	go func() {
		defer wg.Done()
		wsClient.Run(ctx)
	}()

	// 2. Launch Background Collector Loops and track lifecycle
	loops := []func(context.Context, *config.AgentConfig, *ws.Client){
		runHardwareTelemetryLoop,
		runNetworkTelemetryLoop,
		runProcessTelemetryLoop,
		runSecurityEventLoop,
		runAuthMonitorLoop,
		runFIMLoop,
		runSoftwareInventoryLoop,
	}
	for _, loopFn := range loops {
		fn := loopFn
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx, agentCfg, wsClient)
		}()
	}

	// 3. Run Heartbeat Loop (every 30 seconds) and block until cancellation
	runHeartbeatLoop(ctx, agentCfg, wsClient)

	// 4. Await graceful teardown of WebSocket RFC-6455 close handshake and collector loops
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		log.Println("[+] [Lifecycle] All collector loops and WebSocket tunnel terminated cleanly.")
	case <-time.After(5 * time.Second):
		log.Println("[!] [Lifecycle] Graceful teardown deadline elapsed; proceeding with exit.")
	}

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

			if queued := wsClient.SendPriority(payload); queued {
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

	// Dispatch initial hardware telemetry shortly after startup so the dashboard has real CPU/RAM metrics immediately
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1500 * time.Millisecond):
			if frame, err := telemetry.CollectHardwareTelemetry(cfg.AgentID); err == nil {
				if payload, err := json.Marshal(frame); err == nil {
					wsClient.Send(payload)
				}
			}
		}
	}()

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
				log.Printf("[+] [HardwareTelemetry] Host metrics queued (CPU: %.2f%% [%d cores], RAM Used: %.2f%%, Disks: %d, Payload: %d bytes)",
					frame.CPU.UsagePercent,
					frame.CPU.LogicalCores,
					frame.Memory.UsedPercent,
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
		log.Printf("[+] [NetworkTelemetry] Sockets queued (%d active connections, Payload: %d bytes)", len(sockets), len(payload))
	} else {
		log.Printf("[-] [NetworkTelemetry] Outbound buffer saturated; dropped frame for Agent [%s]", agentID)
	}
}

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

func dispatchProcessSnapshot(agentID string, inspector process.Inspector, wsClient *ws.Client) {
	processes, err := inspector.GetRunningProcesses()
	if err != nil {
		log.Printf("[-] [ProcessTelemetry] Inspection failed: %v", err)
		return
	}

	snapshot := process.BuildSnapshot(agentID, processes)
	payload, err := json.Marshal(snapshot)
	if err != nil {
		log.Printf("[-] [ProcessTelemetry] Serialization failed: %v", err)
		return
	}

	if queued := wsClient.Send(payload); queued {
		log.Printf("[+] [ProcessTelemetry] Snapshot queued (%d active processes, Payload: %d bytes)", len(processes), len(payload))
	} else {
		log.Printf("[-] [ProcessTelemetry] Outbound buffer saturated; dropped frame for Agent [%s]", agentID)
	}
}

func runSecurityEventLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	watcher := eventlog.NewWatcher()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	// Initial immediate security log poll on startup
	go dispatchSecurityEvents(cfg.AgentID, watcher, wsClient)

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [SecurityEvent] Context cancelled. Terminating event log loop.")
			return
		case <-ticker.C:
			go dispatchSecurityEvents(cfg.AgentID, watcher, wsClient)
		}
	}
}

func dispatchSecurityEvents(agentID string, watcher *eventlog.Watcher, wsClient *ws.Client) {
	events, err := watcher.ReadSecurityEvents(10)
	if err != nil {
		log.Printf("[-] [SecurityEvent] Event log read error: %v", err)
		return
	}

	if len(events) == 0 {
		return
	}

	frame := eventlog.BuildSecurityEventFrame(agentID, events)
	payload, err := json.Marshal(frame)
	if err != nil {
		log.Printf("[-] [SecurityEvent] Serialization failure: %v", err)
		return
	}

	if queued := wsClient.SendPriority(payload); queued {
		log.Printf("[+] [SecurityEvent] Critical security events dispatched (%d events, Payload: %d bytes)", len(events), len(payload))
	} else {
		log.Printf("[-] [SecurityEvent] Outbound buffer saturated; dropped event frame for Agent [%s]", agentID)
	}
}

func runAuthMonitorLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	watcher := authmon.NewWatcher()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [AuthMon] Context cancelled. Terminating authentication monitor loop.")
			return
		case <-ticker.C:
			events, err := watcher.ReadNewEvents()
			if err != nil {
				log.Printf("[-] [AuthMon] Inspection error: %v", err)
				continue
			}

			if len(events) == 0 {
				continue
			}

			frame := authmon.BuildAuthEventFrame(cfg.AgentID, events)
			payload, err := json.Marshal(frame)
			if err != nil {
				log.Printf("[-] [AuthMon] JSON serialization fault: %v", err)
				continue
			}

			if queued := wsClient.SendPriority(payload); queued {
				log.Printf("[+] [AuthMon] Forensic events dispatched (%d events, Payload: %d bytes)", len(events), len(payload))
			} else {
				log.Printf("[-] [AuthMon] Outbound buffer saturated; dropped frame for Agent [%s]", cfg.AgentID)
			}
		}
	}
}

func runFIMLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	scanner := fim.NewScanner(nil)
	scanner.InitializeBaseline()
	log.Println("[+] [FIM] Cryptographic baseline established for critical system paths.")

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [FIM] Context cancelled. Terminating file integrity loop.")
			return
		case <-ticker.C:
			alerts := scanner.ScanTargets()
			if len(alerts) == 0 {
				continue
			}

			frame := fim.BuildFIMReportFrame(cfg.AgentID, alerts)
			payload, err := json.Marshal(frame)
			if err != nil {
				log.Printf("[-] [FIM] JSON serialization fault: %v", err)
				continue
			}

			if queued := wsClient.SendPriority(payload); queued {
				log.Printf("[!] [FIM] Cryptographic drift alerts dispatched (%d alerts, Payload: %d bytes)", len(alerts), len(payload))
			} else {
				log.Printf("[-] [FIM] Outbound buffer saturated; dropped frame for Agent [%s]", cfg.AgentID)
			}
		}
	}
}

func runSoftwareInventoryLoop(ctx context.Context, cfg *config.AgentConfig, wsClient *ws.Client) {
	ticker := time.NewTicker(600 * time.Second)
	defer ticker.Stop()

	// Initial immediate software inventory scrape on startup
	go dispatchSoftwareInventory(cfg.AgentID, wsClient)

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [SoftwareInventory] Context cancelled. Terminating inventory loop.")
			return
		case <-ticker.C:
			go dispatchSoftwareInventory(cfg.AgentID, wsClient)
		}
	}
}

func dispatchSoftwareInventory(agentID string, wsClient *ws.Client) {
	softwareList, err := inventory.ExtractInstalledSoftware()
	if err != nil {
		log.Printf("[-] [SoftwareInventory] Extraction failure: %v", err)
		return
	}

	frame := inventory.SoftwareInventoryFrame{
		Type:      "software_inventory",
		AgentID:   agentID,
		Timestamp: time.Now().Unix(),
		Software:  softwareList,
	}

	payload, err := json.Marshal(frame)
	if err != nil {
		log.Printf("[-] [SoftwareInventory] Serialization error: %v", err)
		return
	}

	if queued := wsClient.Send(payload); queued {
		log.Printf("[+] [SoftwareInventory] Inventory queued (%d installed packages, Payload: %d bytes)",
			len(softwareList), len(payload))
	} else {
		log.Printf("[-] [SoftwareInventory] Outbound buffer saturated; dropped frame for Agent [%s]", agentID)
	}
}
