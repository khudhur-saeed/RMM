//go:build windows

package netstat

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet                 = 2  // AF_INET: IPv4
	tcpTableOwnerPIDAll    = 5  // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPID       = 1  // UDP_TABLE_OWNER_PID
	errorInsufficientBuffer = 122 // ERROR_INSUFFICIENT_BUFFER
)

// mibTcpRowOwnerPID represents MIB_TCPROW_OWNER_PID in Win32 API.
type mibTcpRowOwnerPID struct {
	dwState      uint32
	dwLocalAddr  uint32
	dwLocalPort  uint32
	dwRemoteAddr uint32
	dwRemotePort uint32
	dwOwningPid  uint32
}

// mibUdpRowOwnerPID represents MIB_UDPROW_OWNER_PID in Win32 API.
type mibUdpRowOwnerPID struct {
	dwLocalAddr uint32
	dwLocalPort uint32
	dwOwningPid uint32
}

// WindowsInspector implements socket enumeration using direct Win32 iphlpapi calls.
type WindowsInspector struct{}

// NewInspector constructs a platform-specific network inspector for Windows.
func NewInspector() *WindowsInspector {
	return &WindowsInspector{}
}

// GetActiveSockets calls native Win32 APIs and returns active listening and established sockets.
func (wi *WindowsInspector) GetActiveSockets() ([]SocketEntry, error) {
	var entries []SocketEntry

	tcpEntries, err := getWindowsTCPConnections()
	if err == nil {
		entries = append(entries, tcpEntries...)
	}

	udpEntries, err := getWindowsUDPListeners()
	if err == nil {
		entries = append(entries, udpEntries...)
	}

	return entries, nil
}

// getWindowsTCPConnections queries GetExtendedTcpTable for IPv4 sockets.
func getWindowsTCPConnections() ([]SocketEntry, error) {
	var size uint32

	// Initial probe to determine required memory buffer size
	ret, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder = TRUE (sorted)
		uintptr(afInet),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)

	if ret != uintptr(errorInsufficientBuffer) && ret != 0 {
		return nil, fmt.Errorf("initial TCP sizing call failed with code: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(afInet),
		uintptr(tcpTableOwnerPIDAll),
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed with code: %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTcpRowOwnerPID{})
	offset := uintptr(4) // Skip dwNumEntries header

	var results []SocketEntry

	for i := uint32(0); i < numEntries; i++ {
		row := (*mibTcpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		state := mapWindowsTCPState(row.dwState)

		// Filter criteria: Keep only LISTEN and ESTABLISHED sockets
		if state != StateListen && state != StateEstablished {
			continue
		}

		localIP := intToIPv4(row.dwLocalAddr)
		remoteIP := intToIPv4(row.dwRemoteAddr)
		localPort := decodeWindowsPort(row.dwLocalPort)
		remotePort := decodeWindowsPort(row.dwRemotePort)

		results = append(results, SocketEntry{
			Protocol: ProtocolTCP,
			Local: IPEndPoint{
				IP:   localIP,
				Port: localPort,
			},
			Remote: IPEndPoint{
				IP:   remoteIP,
				Port: remotePort,
			},
			State: state,
			PID:   int(row.dwOwningPid),
		})
	}

	return results, nil
}

// getWindowsUDPListeners queries GetExtendedUdpTable for IPv4 listeners.
func getWindowsUDPListeners() ([]SocketEntry, error) {
	var size uint32

	ret, _, _ := procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(afInet),
		uintptr(udpTableOwnerPID),
		0,
	)

	if ret != uintptr(errorInsufficientBuffer) && ret != 0 {
		return nil, fmt.Errorf("initial UDP sizing call failed with code: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(afInet),
		uintptr(udpTableOwnerPID),
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed with code: %d", ret)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibUdpRowOwnerPID{})
	offset := uintptr(4)

	var results []SocketEntry

	for i := uint32(0); i < numEntries; i++ {
		row := (*mibUdpRowOwnerPID)(unsafe.Pointer(&buf[offset]))
		offset += rowSize

		localIP := intToIPv4(row.dwLocalAddr)
		localPort := decodeWindowsPort(row.dwLocalPort)

		results = append(results, SocketEntry{
			Protocol: ProtocolUDP,
			Local: IPEndPoint{
				IP:   localIP,
				Port: localPort,
			},
			Remote: IPEndPoint{
				IP:   "0.0.0.0",
				Port: 0,
			},
			State: StateListen,
			PID:   int(row.dwOwningPid),
		})
	}

	return results, nil
}

// decodeWindowsPort converts 32-bit network-byte-order port integer to uint16 host order.
func decodeWindowsPort(rawPort uint32) uint16 {
	var b [2]byte
	b[0] = byte(rawPort)
	b[1] = byte(rawPort >> 8)
	return binary.BigEndian.Uint16(b[:])
}

// intToIPv4 converts a 32-bit unsigned integer to dotted-decimal IPv4 string.
func intToIPv4(ipInt uint32) string {
	ip := make(net.IP, 4)
	ip[0] = byte(ipInt)
	ip[1] = byte(ipInt >> 8)
	ip[2] = byte(ipInt >> 16)
	ip[3] = byte(ipInt >> 24)
	return ip.String()
}

// mapWindowsTCPState maps MIB_TCP_STATE constants to normalized RFC 793 SocketState constants.
func mapWindowsTCPState(state uint32) SocketState {
	switch state {
	case 1:
		return StateClosed
	case 2:
		return StateListen
	case 3:
		return StateSynSent
	case 4:
		return StateSynRecv
	case 5:
		return StateEstablished
	case 6:
		return StateFinWait1
	case 7:
		return StateFinWait2
	case 8:
		return StateCloseWait
	case 9:
		return StateClosing
	case 10:
		return StateLastAck
	case 11:
		return StateTimeWait
	default:
		return StateUnknown
	}
}