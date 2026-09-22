package ws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// Config encapsulates parameters required to establish a secure C2 tunnel
type Config struct {
	ServerURL  string
	AgentID    string
	APIKey     string
	CACertPath string
}

// Client represents the resilient Go WebSocket management client
type Client struct {
	cfg    Config
	dialer *websocket.Dialer
}

// NewClient initializes the WebSocket client enforcing TLS 1.3 and custom Root CA validation
func NewClient(cfg Config) (*Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.CACertPath != "" {
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate for websocket: %w", err)
		}

		rootPool := x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse valid PEM from CA certificate")
		}
		tlsConfig.RootCAs = rootPool
	}

	dialer := &websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: 15 * time.Second,
	}

	return &Client{
		cfg:    cfg,
		dialer: dialer,
	}, nil
}

// buildWebSocketURL converts http(s) into ws(s) and appends handshake credentials
func (c *Client) buildWebSocketURL() (string, error) {
	parsed, err := url.Parse(c.cfg.ServerURL)
	if err != nil {
		return "", fmt.Errorf("invalid server url: %w", err)
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

// Run starts the persistent full-duplex tunnel with exponential backoff resilience
func (c *Client) Run(ctx context.Context) {
	backoff := 2 * time.Second
	maxBackoff := 60 * time.Second

	for {
		select {
		case <-ctx.Done():
			log.Println("[WS] Context cancelled. Exiting WebSocket worker.")
			return
		default:
		}

		wsURL, err := c.buildWebSocketURL()
		if err != nil {
			log.Printf("[WS] URL build error: %v", err)
			return
		}

		log.Printf("[WS] Attempting secure C2 handshake: %s/api/v1/ws/agent/%s?token=***",
			strings.Split(wsURL, "/api/v1")[0], c.cfg.AgentID)

		conn, resp, err := c.dialer.DialContext(ctx, wsURL, nil)
		if err != nil {
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}
			log.Printf("[WS] Connection failed (HTTP Status: %d): %v. Retrying in %v...", statusCode, err, backoff)

			select {
			case <-time.After(backoff):
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			case <-ctx.Done():
				return
			}
		}

		// Reset backoff on successful handshake
		backoff = 2 * time.Second
		log.Printf("[WS] Secure full-duplex tunnel established with control plane.")

		c.handleConnection(ctx, conn)
	}
}

// handleConnection manages frame reads and clean disconnection
func (c *Client) handleConnection(ctx context.Context, conn *websocket.Conn) {
	defer conn.Close()

	// Channel to signal read loop termination
	closed := make(chan struct{})

	go func() {
		for {
			messageType, payload, err := conn.ReadMessage()
			if err != nil {
				log.Printf("[WS] Read error / socket disconnected: %v", err)
				close(closed)
				return
			}
			log.Printf("[WS] Received frame (Type %d, Bytes %d): %s", messageType, len(payload), string(payload))
		}
	}()

	select {
	case <-ctx.Done():
		log.Println("[WS] Terminating socket connection gracefully...")
		closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent shutting down")
		_ = conn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(2*time.Second))
		select {
		case <-closed:
		case <-time.After(1 * time.Second):
		}
	case <-closed:
		log.Println("[WS] Socket closed by remote peer or network drop.")
	}
}
