package system 

import (
	"fmt"
	"net"
	"os"
	"runtime"
)
// HostInfo holds low-level identity and network telemetry extracted from the endpoint.
type HostInfo struct{
	Hostname	string	`json:"hostname"`
	OS			string 	`json:"os"`
	PrivateIP	string	`json:"private_ip"`
	MACAddresses	[]string 	`json:"mac_addresses"`
	HardwareUUID string   `json:"hardware_uuid"`
}

// CollectHostInfo gathers the foundational host properties and network configuration.
func CollectHostInfo() (*HostInfo, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	platform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	macAddrs, primaryIP := collectNetworkDetails()

	return &HostInfo{
		Hostname:     hostname,
		OS:           platform,
		PrivateIP:    primaryIP,
		MACAddresses: macAddrs,
		HardwareUUID: GetOrCreateHardwareUUID(macAddrs, hostname),
	}, nil
}

// collectNetworkDetails iterates active interfaces to capture valid MACs and a private IPv4.
func collectNetworkDetails() ([]string, string) {
	var macs []string
	var primaryIP string

	interfaces, err := net.Interfaces()
	if err != nil {
		return macs, primaryIP
	}

	for _, iface := range interfaces {
		
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		mac := iface.HardwareAddr.String()
		if mac != "" {
			macs = append(macs, mac)
		}

		
		if primaryIP == "" {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					primaryIP = ipNet.IP.String()
					break
				}
			}
		}
	}

	return macs, primaryIP
}