package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"tactical-rmm/agent/internal/client"
	"tactical-rmm/agent/internal/config"
	"tactical-rmm/agent/internal/system"
)

func main() {
	var (
		serverURL  string
		token      string
		caCertPath string
		configPath string
	)

	flag.StringVar(&serverURL, "server", "", "URL of the Tactical RMM control plane (e.g. https://localhost:8000)")
	flag.StringVar(&token, "token", "", "One-time enrollment bootstrap token")
	flag.StringVar(&caCertPath, "ca-cert", "", "Optional path to custom Root CA certificate for TLS validation")
	flag.StringVar(&configPath, "config", config.DefaultConfigFile, "Absolute path to local configuration file")
	flag.Parse()

	// 1. Inspect existing local state configuration
	existingCfg, err := config.LoadConfig(configPath)
	if err == nil && existingCfg.AgentID != "" && existingCfg.APIKey != "" {
		fmt.Printf("[+] Established Agent Identity Found (ID: %s). Ready for Daemon Mode.\n", existingCfg.AgentID)
		return
	}

	// 2. Validate mandatory CLI parameters for bootstrap enrollment
	if serverURL == "" || token == "" {
		fmt.Println("[-] Missing configuration. Either provide an existing config or bootstrap with -server and -token.")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Println("[*] Tactical RMM Agent - Initiating Endpoint Enrollment...")

	// 3. Extract comprehensive host telemetry and persistent hardware identity
	hostInfo, err := system.CollectHostInfo()
	if err != nil {
		log.Fatalf("[-] Critical error capturing system telemetry: %v", err)
	}

	// Ensure hardware UUID is bound to the payload
	hostInfo.HardwareUUID = system.GetOrCreateHardwareUUID(hostInfo.MACAddresses, hostInfo.Hostname)
	fmt.Printf("[+] Host Telemetry Gathered: Hostname=%s, OS=%s, HardwareUUID=%s\n",
		hostInfo.Hostname, hostInfo.OS, hostInfo.HardwareUUID)

	// 4. Initialize TLS-hardened Enrollment Client
	enrollClient, err := client.NewEnrollmentClient(serverURL, caCertPath, 15*time.Second)
	if err != nil {
		log.Fatalf("[-] Failed to configure HTTPS enrollment client: %v", err)
	}

	// 5. Transmit telemetry over HTTPS and parse issued credentials
	fmt.Printf("[*] Dispatching enrollment request to %s/api/v1/enroll...\n", serverURL)
	enrollResp, err := enrollClient.EnrollEndpoint(token, hostInfo)
	if err != nil {
		log.Fatalf("[-] Endpoint enrollment failed: %v", err)
	}

	fmt.Printf("[+] Enrollment Successful: Assigned Agent ID = %s\n", enrollResp.ID)

	// 6. Atomically persist permanent identity and API key
	agentCfg := &config.AgentConfig{
		ServerURL:    serverURL,
		AgentID:      enrollResp.ID,
		APIKey:       enrollResp.APIKey,
		CACertPath:   caCertPath,
		HardwareUUID: hostInfo.HardwareUUID,
	}

	if err := config.SaveConfig(agentCfg, configPath); err != nil {
		log.Fatalf("[-] Failed to atomically persist credentials to %s: %v", configPath, err)
	}

	fmt.Printf("[+] Credentials securely persisted to %s (Permissions: 0600).\n", configPath)
	fmt.Println("[*] Agent bootstrapping sequence completed successfully.")
}
