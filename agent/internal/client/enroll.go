package client

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	ID                  string    `json:"id"`
	SiteID              string    `json:"site_id"`
	Hostname            string    `json:"hostname"`
	OS                  string    `json:"os"`
	PrivateIP           string    `json:"private_ip"`
	PublicIP            string    `json:"public_ip"`
	APIKey              string    `json:"api_key"`
	SigningPublicKey    string    `json:"signing_public_key,omitempty"`
	SigningPublicKeyPEM string    `json:"signing_public_key_pem,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}

// PublicKeyResponse matches the FastAPI PublicKeyRead schema (/api/v1/keys/public)
type PublicKeyResponse struct {
	Algorithm         string `json:"algorithm"`
	PublicKeyB64      string `json:"public_key_b64"`
	PublicKeyPEM      string `json:"public_key_pem"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

// EnrollmentClient orchestrates identity dispatch and secure TLS server validation
type EnrollmentClient struct {
	ServerURL  string
	HTTPClient *http.Client
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

// NewEnrollmentClient initializes an HTTP client pinned to an optional custom Root CA
func NewEnrollmentClient(serverURL string, caCertPath string, timeout time.Duration) (*EnrollmentClient, error) {
	parsedURL, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q", serverURL)
	}

	if parsedURL.Scheme != "https" && !(parsedURL.Scheme == "http" && isLoopbackHost(parsedURL.Host)) {
		return nil, fmt.Errorf("insecure transport rejected: server URL %q must use HTTPS for non-loopback targets", serverURL)
	}

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

// ConfigureTLS applies optional mTLS client certificate authentication and leaf/SPKI SHA-256 certificate pinning.
func (c *EnrollmentClient) ConfigureTLS(clientCertPath, clientKeyPath, certPinSHA256 string) error {
	transport, ok := c.HTTPClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		return fmt.Errorf("enrollment client transport lacks TLS configuration")
	}
	tlsConfig := transport.TLSClientConfig

	if clientCertPath != "" || clientKeyPath != "" {
		if clientCertPath == "" || clientKeyPath == "" {
			return fmt.Errorf("both clientCertPath and clientKeyPath must be provided for mTLS")
		}
		pair, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load mTLS client keypair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
	}

	pin := strings.ToLower(strings.TrimSpace(strings.ReplaceAll(certPinSHA256, ":", "")))
	if pin != "" {
		if _, err := hex.DecodeString(pin); err != nil || len(pin) != 64 {
			return fmt.Errorf("invalid SHA-256 certificate pin %q: expected 64 hex characters", certPinSHA256)
		}
		expectedPin := []byte(pin)
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, raw := range rawCerts {
				certSum := sha256.Sum256(raw)
				certHex := []byte(hex.EncodeToString(certSum[:]))
				if subtle.ConstantTimeCompare(certHex, expectedPin) == 1 {
					return nil
				}
				if parsed, err := x509.ParseCertificate(raw); err == nil {
					spkiSum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
					spkiHex := []byte(hex.EncodeToString(spkiSum[:]))
					if subtle.ConstantTimeCompare(spkiHex, expectedPin) == 1 {
						return nil
					}
				}
			}
			return fmt.Errorf("TLS certificate pin verification failed: no peer certificate matched pin %s", pin)
		}
	}

	return nil
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

// FetchServerPublicKey retrieves the server's active Ed25519 verification public key.
func (c *EnrollmentClient) FetchServerPublicKey() (*PublicKeyResponse, error) {
	endpointURL := fmt.Sprintf("%s/api/v1/keys/public", strings.TrimRight(c.ServerURL, "/"))
	req, err := http.NewRequest(http.MethodGet, endpointURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build public key request: %w", err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch server public key: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("public key request rejected (status %d): %s", resp.StatusCode, string(respBytes))
	}

	var pubResp PublicKeyResponse
	if err := json.Unmarshal(respBytes, &pubResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key response: %w", err)
	}

	return &pubResp, nil
}