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

	agentExec "tactical-rmm/agent/internal/exec"

	"github.com/gorilla/websocket"
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

type CommandPayload struct {
	Type      string `json:"type"`
	CommandID string `json:"cmd_id"`
	Command   string `json:"command"`
}

type CommandResponseFrame struct {
	Type            string `json:"type"`
	CommandID       string `json:"cmd_id"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	ExecutionTimeMs int64  `json:"execution_time_ms"`
	Error           string `json:"error,omitempty"`
}

type Client struct {
	config       Config
	dialer       websocket.Dialer
	outboundChan chan []byte
	executor     agentExec.CommandExecutor
	mu           sync.Mutex
	isConnected  bool
}

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
		executor:     agentExec.NewExecutor(),
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

func (c *Client) Send(payload []byte) bool {
	select {
	case c.outboundChan <- payload:
		return true
	default:
		return false
	}
}

func (c *Client) Run(ctx context.Context) {
	baseBackoff := 1 * time.Second
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

		// Detect and parse command execution requests
		var cmd CommandPayload
		if err := json.Unmarshal(message, &cmd); err == nil && cmd.Type == "exec_cmd" {
			log.Printf("[+] [WS] Received remote command [%s]: %s", cmd.CommandID, cmd.Command)
			go c.handleCommandExecution(ctx, cmd)
			continue
		}

		log.Printf("[*] [WS] Unhandled message payload: %s", string(message))
	}
}

func (c *Client) handleCommandExecution(ctx context.Context, cmd CommandPayload) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[-] [Panic] Command execution worker recovered: %v", r)
		}
	}()

	cmdCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	result, err := c.executor.Execute(cmdCtx, cmd.Command)

	response := CommandResponseFrame{
		Type:            "command_result",
		CommandID:       cmd.CommandID,
		Stdout:          result.Stdout,
		Stderr:          result.Stderr,
		ExitCode:        result.ExitCode,
		ExecutionTimeMs: result.ExecutionTimeMs,
	}

	if err != nil {
		response.Error = err.Error()
	}

	payload, encErr := json.Marshal(response)
	if encErr != nil {
		log.Printf("[-] [WS] Failed to encode command result frame: %v", encErr)
		return
	}

	if !c.Send(payload) {
		log.Printf("[-] [WS] Failed to queue result for command [%s]: outbound buffer full", cmd.CommandID)
	} else {
		log.Printf("[+] [WS] Queued execution result for command [%s] (Exit Code: %d, Time: %dms)",
			cmd.CommandID, result.ExitCode, result.ExecutionTimeMs)
	}
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
