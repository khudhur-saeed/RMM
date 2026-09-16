package main

import (
	"encoding/json"
	"fmt"
	"log"
	"tactical-rmm/agent/internal/system"
)

func main() {
	fmt.Println("[*] Tactical RMM Agent - Probing Host Telemetry...")

	hostData, err := system.CollectHostInfo()
	if err != nil {
		log.Fatalf("[-] Critical error collecting host telemetry: %v", err)
	}

	payload, err := json.MarshalIndent(hostData, "", "  ")
	if err != nil {
		log.Fatalf("[-] Failed to serialize telemetry payload: %v", err)
	}
	fmt.Println("[+] Host Telemetry Successfully Collected:")
	fmt.Println(string(payload))
}
