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

const (
	// pongWait is the maximum time to wait for the next pong from the peer
	pongWait = 60 * time.Second
)

// Config encapsulates parameters required to establish a secure C2 tunnel
type Config struct {
	ServerURL  string
	AgentID    string
	APIKey     string
	CACertPath string
}

// Client represents the resilient Go WebSocket management client with decoupled I/O
type Client struct {
	cfg          Config
	dialer       *websocket.Dialer
	outboundChan chan []byte
}

// NewClient initializes the WebSocket client enforcing TLS 1.3, custom Root CA, and channel allocation
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
		cfg:          cfg,
		dialer:       dialer,
		outboundChan: make(chan []byte, 64),
	}, nil
}

// Send queues a payload into the thread-safe outbound channel without blocking on network I/O
func (c *Client) Send(data []byte) bool {
	select {
	case c.outboundChan <- data:
		return true
	default:
		log.Println("[-] [WS] Outbound channel full! Dropping packet to prevent agent freeze.")
		return false
	}
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
			log.Println("[*] [WS] Context cancelled. Exiting WebSocket worker.")
			return
		default:
		}

		wsURL, err := c.buildWebSocketURL()
		if err != nil {
			log.Printf("[-] [WS] URL build error: %v", err)
			return
		}

		log.Printf("[*] [WS] Attempting secure C2 handshake: %s/api/v1/ws/agent/%s?token=***",
			strings.Split(wsURL, "/api/v1")[0], c.cfg.AgentID)

		conn, resp, err := c.dialer.DialContext(ctx, wsURL, nil)
		if err != nil {
			statusCode := 0
			if resp != nil {
				statusCode = resp.StatusCode
			}
			log.Printf("[-] [WS] Connection failed (HTTP Status: %d): %v. Retrying in %v...", statusCode, err, backoff)

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
		log.Printf("[+] [WS] Secure full-duplex tunnel established with control plane.")

		c.handleConnection(ctx, conn)
	}
}

// handleConnection orchestrates concurrent reader, writer routines, and pong handling
func (c *Client) handleConnection(ctx context.Context, conn *websocket.Conn) {
	defer conn.Close()

	sessionCtx, cancelSession := context.WithCancel(ctx)
	defer cancelSession()

	// 1. Configure Pong Handler and Read Deadline
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(appData string) error {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		log.Printf("[+] [WS] Pong received from server (Data: %s)", appData)
		return nil
	})

	// 2. Dedicated Outgoing Writer Goroutine
	go func() {
		for {
			select {
			case <-sessionCtx.Done():
				return
			case msg, ok := <-c.outboundChan:
				if !ok {
					return
				}
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					log.Printf("[-] [WS] Socket write error: %v", err)
					cancelSession()
					return
				}
			}
		}
	}()

	// 3. Dedicated Inbound Reader Loop (Blocks safely on socket)
	for {
		messageType, payload, err := conn.ReadMessage()
		if err != nil {
			log.Printf("[-] [WS] Socket read error / keep-alive timeout: %v", err)
			cancelSession()
			break
		}

		log.Printf("[+] [WS] Inbound Frame (Type %d, Bytes %d): %s", messageType, len(payload), string(payload))
	}

	// 4. Graceful Close Handshake
	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent socket recycling")
	_ = conn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(1*time.Second))
}