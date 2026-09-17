package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"tactical-rmm/agent/internal/system"
)

// EnrollmentPayload matches the FastAPI AgentEnroll schema
type EnrollmentPayload struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	PrivateIP    string `json:"private_ip"`
	Token        string `json:"token"`
	HardwareUUID string `json:"hardware_uuid"`
}

// EnrollmentResponse matches the FastAPI AgentEnrollResponse schema
type EnrollmentResponse struct {
	ID        string    `json:"id"`
	SiteID    string    `json:"site_id"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	PrivateIP string    `json:"private_ip"`
	PublicIP  string    `json:"public_ip"`
	APIKey    string    `json:"api_key"`
	CreatedAt time.Time `json:"created_at"`
}

// EnrollmentClient orchestrates identity dispatch and secure TLS server validation
type EnrollmentClient struct {
	ServerURL  string
	HTTPClient *http.Client
}

// NewEnrollmentClient initializes an HTTP client pinned to an optional custom Root CA
func NewEnrollmentClient(serverURL string, caCertPath string, timeout time.Duration) (*EnrollmentClient, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read target CA cert: %w", err)
		}

		rootPool := x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse valid PEM from CA certificate")
		}
		tlsConfig.RootCAs = rootPool
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		ResponseHeaderTimeout: 10 * time.Second,
	}

	return &EnrollmentClient{
		ServerURL: serverURL,
		HTTPClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
	}, nil
}

// EnrollEndpoint transmits host telemetry and parses permanent credentials
func (c *EnrollmentClient) EnrollEndpoint(token string, host *system.HostInfo) (*EnrollmentResponse, error) {
	payload := EnrollmentPayload{
		Hostname:     host.Hostname,
		OS:           host.OS,
		PrivateIP:    host.PrivateIP,
		Token:        token,
		HardwareUUID: host.HardwareUUID,
	}

	rawBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize enrollment payload: %w", err)
	}

	endpointURL := fmt.Sprintf("%s/api/v1/enroll", c.ServerURL)
	req, err := http.NewRequest(http.MethodPost, endpointURL, bytes.NewBuffer(rawBody))
	if err != nil {
		return nil, fmt.Errorf("failed to build HTTP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tls handshake or transport failure: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read server response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enrollment rejected (status %d): %s", resp.StatusCode, string(respBytes))
	}

	var enrollResp EnrollmentResponse
	if err := json.Unmarshal(respBytes, &enrollResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	return &enrollResp, nil
}