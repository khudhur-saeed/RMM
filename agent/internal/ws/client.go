package ws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"tactical-rmm/agent/internal/terminal"
)

// Config encapsulates connection parameters for the secure C2 WebSocket tunnel.
type Config struct {
	ServerURL  string
	AgentID    string
	APIKey     string
	CACertPath string
}

// InboundEnvelope defines the discriminator for demultiplexing incoming frames.
type InboundEnvelope struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

// Client represents the persistent WebSocket agent control plane client.
type Client struct {
	cfg          Config
	dialer       *websocket.Dialer
	conn         *websocket.Conn
	outboundChan chan []byte

	// PTY Interactive Session Management
	termSession *terminal.Session
	termMutex   sync.Mutex

	connMutex sync.Mutex
	isClosed  bool
	closeOnce sync.Once
}

// NewClient initializes the WebSocket client enforcing TLS 1.3 and optional Root CA validation.
func NewClient(cfg Config) (*Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		rootPool := x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse valid PEM from CA certificate")
		}
		tlsConfig.RootCAs = rootPool
	}

	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 10 * time.Second,
	}

	return &Client{
		cfg:          cfg,
		dialer:       dialer,
		outboundChan: make(chan []byte, 128),
	}, nil
}

// buildWebSocketURL converts http(s) into ws(s) and appends authentication parameters.
func (c *Client) buildWebSocketURL() (string, error) {
	parsed, err := url.Parse(c.cfg.ServerURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	scheme := "wss"
	if parsed.Scheme == "http" {
		scheme = "ws"
	}

	wsPath := fmt.Sprintf("%s/api/v1/ws/agent/%s", strings.TrimRight(parsed.Path, "/"), c.cfg.AgentID)
	q := url.Values{}
	q.Set("token", c.cfg.APIKey)

	u := url.URL{
		Scheme:   scheme,
		Host:     parsed.Host,
		Path:     wsPath,
		RawQuery: q.Encode(),
	}

	return u.String(), nil
}

// Send enqueues payload bytes into the outbound channel without blocking the caller.
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
		log.Println("[-] [WS] Outbound buffer saturated. Dropping frame.")
		return false
	}
}

// Run executes the continuous connection supervisor with automatic reconnection.
func (c *Client) Run(ctx context.Context) {
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
			log.Printf("[-] [WS] URL construction error: %v", err)
			return
		}

		log.Printf("[*] [WS] Attempting secure C2 handshake: %s/api/v1/ws/agent/%s?token=***",
			strings.Split(wsURL, "/api/v1")[0], c.cfg.AgentID)

		conn, resp, err := c.dialer.DialContext(ctx, wsURL, http.Header{})
		if err != nil {
			status := "unknown"
			if resp != nil {
				status = resp.Status
			}
			log.Printf("[-] [WS] Handshake failed (%s): %v. Retrying in 5 seconds...", status, err)

			select {
			case <-time.After(5 * time.Second):
				continue
			case <-ctx.Done():
				return
			}
		}

		log.Printf("[+] [WS] Secure full-duplex tunnel established with control plane.")
		c.connMutex.Lock()
		c.conn = conn
		c.isClosed = false
		c.connMutex.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			c.writerLoop(ctx)
		}()

		go func() {
			defer wg.Done()
			c.readerLoop(ctx)
		}()

		wg.Wait()
		c.cleanupSession()

		log.Println("[-] [WS] Tunnel disconnected. Entering reconnect routine in 3 seconds...")
		select {
		case <-time.After(3 * time.Second):
		case <-ctx.Done():
			return
		}
	}
}

// writerLoop handles thread-safe serialized frame transmissions to the socket.
func (c *Client) writerLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-c.outboundChan:
			if !ok {
				return
			}
			c.connMutex.Lock()
			conn := c.conn
			c.connMutex.Unlock()

			if conn == nil {
				return
			}

			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				log.Printf("[-] [WS] Write failure: %v", err)
				_ = conn.Close()
				return
			}
		}
	}
}

// readerLoop demultiplexes incoming control frames and injects terminal keystrokes into PTY.
func (c *Client) readerLoop(ctx context.Context) {
	defer func() {
		c.connMutex.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
		}
		c.isClosed = true
		c.connMutex.Unlock()
	}()

	for {
		_, message, err := c.conn.ReadMessage()
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
		case "heartbeat":
			// Handled by background telemetry if needed
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
		log.Println("[+] [PTY] Interactive bash shell attached to active session.")
	}

	if err := c.termSession.WriteInput([]byte(payload)); err != nil {
		log.Printf("[-] [PTY] Error writing keystroke to PTY: %v", err)
	}
}

// cleanupSession cleanly terminates the PTY child process upon disconnection.
func (c *Client) cleanupSession() {
	c.termMutex.Lock()
	defer c.termMutex.Unlock()

	if c.termSession != nil {
		c.termSession.Close()
		c.termSession = nil
	}
}

// teardown performs definitive client shutdown.
func (c *Client) teardown() {
	c.closeOnce.Do(func() {
		c.cleanupSession()
		c.connMutex.Lock()
		c.isClosed = true
		if c.conn != nil {
			_ = c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent shutting down"))
			_ = c.conn.Close()
		}
		c.connMutex.Unlock()
	})
}
