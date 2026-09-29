package ws

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	agentExec "tactical-rmm/agent/internal/exec"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512 * 1024 // 512 KB
	defaultTimeout = 30 * time.Second
)

type Config struct {
	ServerURL  string
	AgentID    string
	APIKey     string
	CACertPath string
}

// Client encapsulates the full-duplex WebSocket connection lifecycle.
type Client struct {
	config       Config
	dialer       websocket.Dialer
	outboundChan chan []byte
	mu           sync.Mutex
	isConnected  bool
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

	return &Client{
		config: cfg,
		dialer: websocket.Dialer{
			TLSClientConfig:  tlsConfig,
			HandshakeTimeout: 15 * time.Second,
		},
		outboundChan: make(chan []byte, 64),
	}, nil
}

func (c *Client) buildWebSocketURL() (string, error) {
	parsed, err := url.Parse(c.config.ServerURL)
	if err != nil {
		return "", fmt.Errorf("invalid server URL: %w", err)
	}

	scheme := "ws"
	if parsed.Scheme == "https" {
		scheme = "wss"
	}

	wsURL := fmt.Sprintf("%s://%s/api/v1/ws/agent/%s?token=%s",
		scheme,
		parsed.Host,
		c.config.AgentID,
		c.config.APIKey,
	)

	return wsURL, nil
}

// Send queues a payload onto the outbound channel without blocking the caller.
func (c *Client) Send(payload []byte) bool {
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
			return
		default:
		}

		wsURL, err := c.buildWebSocketURL()
		if err != nil {
			log.Printf("[-] [WS] Configuration error: %v", err)
			return
		}

		log.Printf("[*] [WS] Attempting secure C2 handshake: %s", sanitizeLogURL(wsURL))
		conn, resp, err := c.dialer.DialContext(ctx, wsURL, nil)
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
				return
			}
		}

		currentBackoff = baseBackoff
		c.setConnected(true)
		log.Println("[+] [WS] Secure full-duplex tunnel established with control plane.")

		sessionCtx, cancelSession := context.WithCancel(ctx)
		var sessionWg sync.WaitGroup

		sessionWg.Add(1)
		go func() {
			defer sessionWg.Done()
			c.writePump(sessionCtx, conn)
		}()

		c.readPump(sessionCtx, conn)

		cancelSession()
		conn.Close()
		sessionWg.Wait()

		c.setConnected(false)
		log.Println("[-] [WS] Session disconnected. Entering reconnect routine.")
	}
}

func (c *Client) writePump(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Agent shutting down"),
				time.Now().Add(writeWait),
			)
			return
		case payload, ok := <-c.outboundChan:
			_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				log.Printf("[-] [WS] Socket write error: %v", err)
				return
			}
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("[-] [WS] Keep-alive ping failed: %v", err)
				return
			}
		}
	}
}

func (c *Client) readPump(ctx context.Context, conn *websocket.Conn) {
	conn.SetReadLimit(maxMessageSize)
	_ = conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		_ = conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[-] [WS] Unexpected socket closure: %v", err)
			}
			break
		}

		// Inspect inbound frame type
		var genericFrame struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(message, &genericFrame); err != nil {
			continue
		}

		switch genericFrame.Type {
		case "task_dispatch":
			var dispatchFrame TaskDispatchFrame
			if err := json.Unmarshal(message, &dispatchFrame); err == nil && dispatchFrame.Command != "" {
				log.Printf("[+] [Task] Inbound task dispatch [%s]: %s", dispatchFrame.TaskID, dispatchFrame.Command)
				go c.handleTaskDispatch(dispatchFrame)
			}
		default:
			log.Printf("[*] [WS] Unhandled frame type: %s", genericFrame.Type)
		}
	}
}

// handleTaskDispatch streams execution output live and captures the process exit code.
func (c *Client) handleTaskDispatch(task TaskDispatchFrame) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[-] [Task] Recovered from execution panic on TaskID [%s]: %v", task.TaskID, r)
		}
	}()

	timeout := defaultTimeout
	if task.TimeoutSec > 0 {
		timeout = time.Duration(task.TimeoutSec) * time.Second
	}

	taskCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Chunk callback: Encapsulate each stdout/stderr slice into a live stream frame
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

func (c *Client) setConnected(status bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.isConnected = status
}

func sanitizeLogURL(rawURL string) string {
	idx := strings.Index(rawURL, "token=")
	if idx == -1 {
		return rawURL
	}
	return rawURL[:idx] + "token=***"
}