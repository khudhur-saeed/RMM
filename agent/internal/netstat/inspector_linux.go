//go:build linux

package netstat

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type processMeta struct {
	PID  int
	Name string
}

// LinuxInspector implements socket enumeration using virtual kernel filesystems.
type LinuxInspector struct{}

// NewInspector constructs a platform-specific network inspector for Linux.
func NewInspector() *LinuxInspector {
	return &LinuxInspector{}
}

// GetActiveSockets scans kernel tables and returns active listening and established sockets.
func (li *LinuxInspector) GetActiveSockets() ([]SocketEntry, error) {
	inodeMap := buildSocketInodeMap()

	var entries []SocketEntry

	// Parse IPv4 tables
	tcpEntries, _ := parseProcNetFile("/proc/net/tcp", ProtocolTCP, inodeMap)
	entries = append(entries, tcpEntries...)

	udpEntries, _ := parseProcNetFile("/proc/net/udp", ProtocolUDP, inodeMap)
	entries = append(entries, udpEntries...)

	return entries, nil
}

// buildSocketInodeMap scans /proc/[pid]/fd to map socket inodes to owning processes.
func buildSocketInodeMap() map[uint64]processMeta {
	inodeMap := make(map[uint64]processMeta)

	procEntries, err := os.ReadDir("/proc")
	if err != nil {
		return inodeMap
	}

	for _, procEntry := range procEntries {
		if !procEntry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(procEntry.Name())
		if err != nil {
			// Skip non-process numeric directories in /proc
			continue
		}

		// Read process name from /proc/[pid]/comm
		commBytes, _ := os.ReadFile(filepath.Join("/proc", procEntry.Name(), "comm"))
		procName := strings.TrimSpace(string(commBytes))

		fdDir := filepath.Join("/proc", procEntry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// May fail due to permissions or short-lived processes
			continue
		}

		for _, fd := range fds {
			linkPath := filepath.Join(fdDir, fd.Name())
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			// Socket symlinks match the format "socket:[12345]"
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inodeStr := target[8 : len(target)-1]
				if inode, err := strconv.ParseUint(inodeStr, 10, 64); err == nil {
					inodeMap[inode] = processMeta{
						PID:  pid,
						Name: procName,
					}
				}
			}
		}
	}

	return inodeMap
}

// parseProcNetFile reads /proc/net/tcp or udp line by line and decodes sockets.
func parseProcNetFile(filePath string, proto TransportProtocol, inodeMap map[uint64]processMeta) ([]SocketEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", filePath, err)
	}
	defer file.Close()

	var results []SocketEntry
	scanner := bufio.NewScanner(file)

	// Skip table header line
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// fields: [sl, local_address, rem_address, st, tx_queue:rx_queue, tr:tm->when, retrnsmt, uid, timeout, inode]
		localHex := fields[1]
		remoteHex := fields[2]
		stateHex := fields[3]
		inodeVal, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		localEP, err := parseHexEndPoint(localHex)
		if err != nil {
			continue
		}

		remoteEP, err := parseHexEndPoint(remoteHex)
		if err != nil {
			continue
		}

		state := mapLinuxTCPState(stateHex, proto)

		// Filter criteria: Keep only LISTEN and ESTABLISHED sockets for telemetry baseline
		if proto == ProtocolTCP && state != StateListen && state != StateEstablished {
			continue
		}

		entry := SocketEntry{
			Protocol: proto,
			Local:    localEP,
			Remote:   remoteEP,
			State:    state,
			PID:      0,
		}

		// Match Inode to Process ID
		if meta, found := inodeMap[inodeVal]; found {
			entry.PID = meta.PID
			entry.ProcessName = meta.Name
		}

		results = append(results, entry)
	}

	return results, scanner.Err()
}

// parseHexEndPoint decodes "0100007F:0050" into IP "127.0.0.1" and Port 80.
func parseHexEndPoint(hexEP string) (IPEndPoint, error) {
	parts := strings.Split(hexEP, ":")
	if len(parts) != 2 {
		return IPEndPoint{}, fmt.Errorf("invalid endpoint format")
	}

	ipBytes, err := hex.DecodeString(parts[0])
	if err != nil || len(ipBytes) != 4 {
		return IPEndPoint{}, fmt.Errorf("invalid hex IP payload")
	}

	// IPv4 in /proc/net is stored in Little-Endian byte order
	ip := net.IPv4(ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0]).String()

	portVal, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return IPEndPoint{}, fmt.Errorf("invalid hex port payload")
	}

	return IPEndPoint{
		IP:   ip,
		Port: uint16(portVal),
	}, nil
}

// mapLinuxTCPState maps Linux kernel TCP state hex codes to unified RFC 793 SocketState constants.
func mapLinuxTCPState(stateHex string, proto TransportProtocol) SocketState {
	if proto == ProtocolUDP {
		// UDP is connectionless; bound UDP sockets function as listeners
		return StateListen
	}

	switch strings.ToUpper(stateHex) {
	case "01":
		return StateEstablished
	case "02":
		return StateSynSent
	case "03":
		return StateSynRecv
	case "04":
		return StateFinWait1
	case "05":
		return StateFinWait2
	case "06":
		return StateTimeWait
	case "07":
		return StateClosed
	case "08":
		return StateCloseWait
	case "09":
		return StateLastAck
	case "0A":
		return StateListen
	case "0B":
		return StateClosing
	default:
		return StateUnknown
	}
}
