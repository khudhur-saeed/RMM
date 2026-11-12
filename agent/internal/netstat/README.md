# Network Socket Inspector

## Overview
Cross-platform in-process network socket inspector parsing Linux /proc/net/* tables and process file descriptors or invoking Windows Win32 iphlpapi.dll extended TCP/UDP tables.

## Interface
- Inspector interface [inspector.go:8]: Platform-agnostic socket inspection contract
- NewInspector() *LinuxInspector / *WindowsInspector [inspector_linux.go:25, inspector_windows.go:48]: Platform inspector constructors
- BuildSnapshot(agentID string, sockets []SocketEntry) NetworkSnapshotFrame [inspector.go:13]: Wraps active sockets into C2 telemetry envelope
- TransportProtocol type [types.go:4]: Layer 4 protocol enum (ProtocolTCP, ProtocolUDP)
- SocketState type [types.go:12]: RFC 793 connection state enum (StateListen, StateEstablished, etc.)
- IPEndPoint struct [types.go:29]: IP address and Layer 4 port representation
- SocketEntry struct [types.go:36]: Normalized socket record with Protocol, Local, Remote, State, PID, and ProcessName
- NetworkSnapshotFrame struct [types.go:46]: C2 telemetry transmission frame

## Invariants
- TCP inspection filters strictly for LISTEN and ESTABLISHED connections to establish accurate baseline telemetry [inspector_linux.go:150-152, inspector_windows.go:121-123]
- Linux inspector resolves socket owners by matching socket:[inode] symlinks across /proc/[pid]/fd [inspector_linux.go:52-100]
- Windows inspector uses two-pass buffer sizing for GetExtendedTcpTable and GetExtendedUdpTable to handle dynamic connection table growth [inspector_windows.go:74-99, 152-178]

## Side Effects
- Linux File System: Reads /proc/net/tcp, tcp6, udp, udp6 and inspects /proc/[pid]/fd links and /proc/[pid]/comm
- Windows API: Calls iphlpapi.dll (GetExtendedTcpTable, GetExtendedUdpTable)

## Verification
- Run: `cd agent && go test -v ./internal/...`
