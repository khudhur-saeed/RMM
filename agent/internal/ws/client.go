package ws

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	agentCrypto "tactical-rmm/agent/internal/crypto"
	agentExec "tactical-rmm/agent/internal/exec"
	"tactical-rmm/agent/internal/terminal"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512 * 1024 // 512 KB
	defaultTimeout = 30 * time.Second
)

// Config defines connection parameters for the WebSocket client.
type Config struct {
	ServerURL        string
	AgentID          string
	APIKey           string
	CACertPath       string
	SigningPublicKey string
}

// InboundEnvelope defines the generic discriminator for demultiplexing incoming frames.
type InboundEnvelope struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

// Client encapsulates the full-duplex WebSocket connection lifecycle and interactive sessions.
type Client struct {
	config        Config
	signingPubKey ed25519.PublicKey
	dialer        websocket.Dialer
	conn          *websocket.Conn
	connMutex     sync.Mutex
	outboundChan  chan []byte

	// PTY Interactive Session Management
	termSession *terminal.Session
	termMutex   sync.Mutex

	isClosed  bool
	closeOnce sync.Once
}

func isLoopbackHost(host string) bool {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	hostname = strings.Trim(hostname, "[]")
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// NewClient initializes the WebSocket client enforcing TLS 1.3 and Root CA verification.
func NewClient(cfg Config) (*Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read custom Root CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to append custom Root CA certificate to pool")
		}
		tlsConfig.RootCAs = caCertPool
	}

	var parsedPubKey ed25519.PublicKey
	if strings.TrimSpace(cfg.SigningPublicKey) != "" {
		pub, err := agentCrypto.ParseEd25519PublicKey(cfg.SigningPublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Ed25519 signing public key: %w", err)
		}
		parsedPubKey = pub
	}

	return &Client{
		config:        cfg,
		signingPubKey: parsedPubKey,
		dialer: websocket.Dialer{
			TLSClientConfig:  tlsConfig,
			HandshakeTimeout: 15 * time.Second,
		},
		outboundChan: make(chan []byte, 128),
	}, nil
}

func (c *Client) buildWebSocketURL() (string, error) {
	parsed, err := url.Parse(c.config.ServerURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	var scheme string
	switch parsed.Scheme {
	case "https", "wss":
		scheme = "wss"
	case "http", "ws":
		if !isLoopbackHost(parsed.Host) {
			return "", fmt.Errorf("insecure transport rejected: non-loopback C2 host %q requires wss/https", parsed.Host)
		}
		scheme = "ws"
	default:
		return "", fmt.Errorf("unsupported URL scheme %q", parsed.Scheme)
	}

	wsURL := fmt.Sprintf("%s://%s/api/v1/ws/agent/%s",
		scheme,
		parsed.Host,
		url.PathEscape(c.config.AgentID),
	)

	return wsURL, nil
}

// Send queues a payload onto the outbound channel without blocking the caller.
func (c *Client) Send(payload []byte) bool {
	c.connMutex.Lock()
	closed := c.isClosed
	c.connMutex.Unlock()

	if closed {
		return false
	}

	select {
	case c.outboundChan <- payload:
		return true
	default:
		log.Println("[-] [WS] Outbound buffer saturated; frame dropped")
		return false
	}
}

// Run executes the resilient connection loop with exponential backoff.
func (c *Client) Run(ctx context.Context) {
	baseBackoff := 2 * time.Second
	maxBackoff := 60 * time.Second
	currentBackoff := baseBackoff

	for {
		select {
		case <-ctx.Done():
			log.Println("[*] [WS] Termination signal received. Halting client loop.")
			c.teardown()
			return
		default:
		}

		wsURL, err := c.buildWebSocketURL()
		if err != nil {
			log.Printf("[-] [WS] Configuration error: %v", err)
			return
		}

		headers := http.Header{
			"Authorization": []string{"Bearer " + c.config.APIKey},
		}

		log.Printf("[*] [WS] Attempting secure C2 handshake: %s", sanitizeLogURL(wsURL))
		conn, resp, err := c.dialer.DialContext(ctx, wsURL, headers)
		if err != nil {
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}
			log.Printf("[-] [WS] Connection failed (HTTP Status: %d): %v. Retrying in %v...", statusCode, err, currentBackoff)

			select {
			case <-time.After(currentBackoff):
				currentBackoff *= 2
				if currentBackoff > maxBackoff {
					currentBackoff = maxBackoff
				}
				continue
			case <-ctx.Done():
				c.teardown()
				return
			}
		}

		currentBackoff = baseBackoff
		c.connMutex.Lock()
		c.conn = conn
		c.isClosed = false
		c.connMutex.Unlock()
		log.Println("[+] [WS] Secure full-duplex tunnel established with control plane.")

		sessionCtx, cancelSession := context.WithCancel(ctx)
		var sessionWg sync.WaitGroup

		sessionWg.Add(2)
		go func() {
			defer sessionWg.Done()
			c.writePump(sessionCtx, conn)
		}()

		go func() {
			defer sessionWg.Done()
			c.readPump(sessionCtx, conn)
		}()

		// Block until socket fails or context is cancelled
		sessionWg.Wait()
		cancelSession()

		// Clean up any interactive shell spawned during this session
		c.cleanupSession()

		log.Println("[-] [WS] Session disconnected. Entering reconnect routine in 3 seconds...")
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
			c.teardown()
			return
		}
	}
}

func (c *Client) writePump(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-c.outboundChan:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				log.Printf("[-] [WS] Socket write error: %v", err)
				_ = conn.Close()
				return
			}
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[-] [WS] Keep-alive ping failed: %v", err)
				_ = conn.Close()
				return
			}
		}
	}
}

func (c *Client) readPump(ctx context.Context, conn *websocket.Conn) {
	defer func() {
		c.connMutex.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}
		c.connMutex.Unlock()
	}()

	conn.SetReadLimit(maxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("[-] [WS] Socket error: %v", err)
			}
			break
		}

		var env InboundEnvelope
		if err := json.Unmarshal(message, &env); err != nil {
			continue
		}

		switch env.Type {
		case "term_in":
			c.handleTerminalInput(env.Payload)
		case "task_dispatch":
			var dispatchFrame TaskDispatchFrame
			if err := json.Unmarshal(message, &dispatchFrame); err == nil && dispatchFrame.Command != "" {
				log.Printf("[+] [Task] Inbound task dispatch [%s]: %s", dispatchFrame.TaskID, dispatchFrame.Command)
				go c.handleTaskDispatch(dispatchFrame)
			}
		}
	}
}

// handleTerminalInput manages on-demand PTY allocation and routes keystrokes.
func (c *Client) handleTerminalInput(payload string) {
	c.termMutex.Lock()
	defer c.termMutex.Unlock()

	if c.termSession == nil {
		session, err := terminal.NewSession()
		if err != nil {
			log.Printf("[-] [PTY] Failed to spawn pseudoterminal session: %v", err)
			return
		}
		c.termSession = session
		session.StartOutputPump(c.outboundChan)
		log.Println("[+] [PTY] Interactive shell attached to active session.")
	}

	if err := c.termSession.WriteInput([]byte(payload)); err != nil {
		log.Printf("[-] [PTY] Error writing keystroke to PTY: %v", err)
	}
}

// VerifyTaskDispatch validates the SHA-256 payload digest and Ed25519 signature of an inbound task frame.
func (c *Client) VerifyTaskDispatch(task TaskDispatchFrame) error {
	return agentCrypto.VerifyTaskDispatch(
		c.signingPubKey,
		task.TaskID,
		task.Command,
		task.TimeoutSec,
		task.PayloadSHA256,
		task.Signature,
	)
}

// handleTaskDispatch verifies the Ed25519 signature before streaming execution output live.
// Unsigned or tampered scripts are dropped immediately without execution.
func (c *Client) handleTaskDispatch(task TaskDispatchFrame) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[-] [Task] Recovered from execution panic on TaskID [%s]: %v", task.TaskID, r)
		}
	}()

	if err := c.VerifyTaskDispatch(task); err != nil {
		log.Printf("[!] [Security] Dropped unsigned or tampered task dispatch [%s]: %v", task.TaskID, err)
		return
	}

	timeout := defaultTimeout
	if task.TimeoutSec > 0 {
		timeout = time.Duration(task.TimeoutSec) * time.Second
	}

	taskCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	onChunk := func(streamType string, chunk string) {
		streamFrame := TaskStreamFrame{
			Type:   "task_stream",
			TaskID: task.TaskID,
			Stream: streamType,
			Chunk:  chunk,
		}
		if payload, err := json.Marshal(streamFrame); err == nil {
			c.Send(payload)
		}
	}

	exitCode, elapsedMs, err := agentExec.ExecuteStreaming(taskCtx, task.Command, onChunk)

	exitFrame := TaskExitFrame{
		Type:      "task_exit",
		TaskID:    task.TaskID,
		ExitCode:  exitCode,
		ElapsedMs: elapsedMs,
	}

	if err != nil {
		errStr := err.Error()
		exitFrame.Error = &errStr
	}

	if payload, encErr := json.Marshal(exitFrame); encErr == nil {
		c.Send(payload)
	}

	log.Printf("[+] [Task] Completed TaskID [%s] (ExitCode: %d, Elapsed: %dms)",
		task.TaskID, exitCode, elapsedMs)
}

// cleanupSession cleanly terminates the PTY child process upon disconnection.
func (c *Client) cleanupSession() {
	c.termMutex.Lock()
	defer c.termMutex.Unlock()

	if c.termSession != nil {
		c.termSession.Close()
		c.termSession = nil
		log.Println("[*] [PTY] Interactive session closed and process tree reaped.")
	}
}

// teardown performs definitive client shutdown with RFC-6455 close handshake.
func (c *Client) teardown() {
	c.closeOnce.Do(func() {
		c.cleanupSession()

		c.connMutex.Lock()
		defer c.connMutex.Unlock()

		c.isClosed = true
		if c.conn != nil {
			closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent shutting down")
			deadline := time.Now().Add(2 * time.Second)
			_ = c.conn.WriteControl(websocket.CloseMessage, closeMsg, deadline)
			_ = c.conn.Close()
			c.conn = nil
		}
	})
}

func sanitizeLogURL(rawURL string) string {
	idx := strings.Index(rawURL, "token=")
	if idx == -1 {
		return rawURL
	}
	return rawURL[:idx] + "token=***"
}
