# WebSocket C2 Tunnel Client

## Overview
Full-duplex WebSocket C2 tunnel client providing TLS 1.3 encryption, mTLS, SPKI/cert pinning, exponential backoff reconnection, priority queues, and Ed25519-signed task execution and PTY streaming.

## Interface
- NewClient(cfg Config) (*Client, error) [client.go:123]: Initializes WebSocket client with TLS 1.3, Root CA pool, mTLS, certificate pin, and Ed25519 public key
- (*Client) Run(ctx context.Context) [client.go:262]: Enters resilient C2 connection loop with exponential backoff
- (*Client) Send(payload []byte) bool [client.go:210]: Queues telemetry onto outbound buffer
- (*Client) SendPriority(payload []byte) bool [client.go:235]: Queues high-priority security telemetry or task exits with backpressure fallback
- (*Client) VerifyTaskDispatch(task TaskDispatchFrame) error [client.go:496]: Cryptographically verifies task dispatch before execution
- (*Client) VerifyTermIn(frame TermInFrame) error [client.go:444]: Cryptographically verifies PTY terminal keystroke frames
- VerifyPinnedPeerCert(rawCerts [][]byte, expectedPinHex string) error [client.go:93]: Validates peer TLS certificate chain against SHA-256 pin
- Config struct [client.go:40]: WebSocket client configuration
- Client struct [client.go:58]: WebSocket C2 client session manager
- TaskDispatchFrame, TermInFrame, TaskStreamFrame, TaskExitFrame [protocol.go:3-40]: C2 WebSocket protocol frames

## Invariants
- Plaintext ws:// transport is rejected for all non-loopback destinations [client.go:191-194]
- Inbound tasks and PTY input without a valid Ed25519 digital signature, fresh timestamp window, or matching recipient agent ID are dropped immediately [client.go:464-468, 526-529]
- Exponential backoff reconnect loop backs off from 2 seconds up to 60 seconds max on connection failure [client.go:263-265, 296-300]
- Write pump prioritizes the priority channel before draining standard outbound telemetry frames [client.go:360-372]
- Client shutdown performs RFC-6455 normal closure handshake with a 2-second deadline [client.go:586-602]

## Side Effects
- Network: Establishes persistent TLS WebSocket connection to /api/v1/ws/agent/{agent_id}
- Process Execution: Triggers streaming shell command execution via exec.ExecuteStreaming and spawns interactive PTY sessions via terminal.NewSession

## Verification
- Run: `cd agent && go test -v ./internal/ws/...`
