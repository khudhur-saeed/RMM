package netstat

// TransportProtocol defines supported Layer 4 transport protocols.
type TransportProtocol string

const (
	ProtocolTCP TransportProtocol = "TCP"
	ProtocolUDP TransportProtocol = "UDP"
)

// SocketState represents normalized TCP/UDP connection states based on RFC 793.
type SocketState string

const (
	StateListen      SocketState = "LISTEN"
	StateEstablished SocketState = "ESTABLISHED"
	StateSynSent     SocketState = "SYN_SENT"
	StateSynRecv     SocketState = "SYN_RECV"
	StateFinWait1    SocketState = "FIN_WAIT1"
	StateFinWait2    SocketState = "FIN_WAIT2"
	StateTimeWait    SocketState = "TIME_WAIT"
	StateCloseWait   SocketState = "CLOSE_WAIT"
	StateClosing     SocketState = "CLOSING"
	StateLastAck     SocketState = "LAST_ACK"
	StateClosed      SocketState = "CLOSED"
	StateUnknown     SocketState = "UNKNOWN"
)

// IPEndPoint represents an IP address and associated Layer 4 port.
type IPEndPoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// SocketEntry encapsulates telemetry for an active listening port or established socket.
type SocketEntry struct {
	Protocol    TransportProtocol `json:"protocol"`
	Local       IPEndPoint        `json:"local"`
	Remote      IPEndPoint        `json:"remote"`
	State       SocketState       `json:"state"`
	PID         int               `json:"pid"`
	ProcessName string            `json:"process_name,omitempty"`
}

// NetworkSnapshotFrame aggregates active socket telemetry for transmission over C2 tunnels.
type NetworkSnapshotFrame struct {
	Type      string        `json:"type"`
	AgentID   string        `json:"agent_id"`
	Timestamp int64         `json:"timestamp"`
	Sockets   []SocketEntry `json:"sockets"`
}