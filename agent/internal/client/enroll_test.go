package client_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tactical-rmm/agent/internal/client"
	"tactical-rmm/agent/internal/config"
	"tactical-rmm/agent/internal/system"
)

func TestEndToEndEnrollmentAndPermissionEnforcement(t *testing.T) {
	expectedToken := "sec_tok_test_bootstrap_token_123"
	expectedAgentID := "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	expectedAPIKey := "rmm_sec_live_test_credential_secret_abc"

	// 1. Initialize local HTTP mock server simulating the FastAPI enrollment endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST method, got %s", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if r.URL.Path != "/api/v1/enroll" {
			t.Errorf("expected path /api/v1/enroll, got %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		var payload client.EnrollmentPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if payload.Token != expectedToken {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// Return HTTP 201 Created with mock registration credentials
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		resp := client.EnrollmentResponse{
			ID:        expectedAgentID,
			SiteID:    "e6c1e5d3-8b7a-42c2-84b3-b4a6d0c2e1f8",
			Hostname:  payload.Hostname,
			OS:        payload.OS,
			PrivateIP: payload.PrivateIP,
			APIKey:    expectedAPIKey,
			CreatedAt: time.Now().UTC(),
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// 2. Build isolated test filesystem
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	// 3. Initialize enrollment client pointing to the mock server
	enrollClient, err := client.NewEnrollmentClient(mockServer.URL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("failed to initialize enrollment client: %v", err)
	}

	hostInfo := &system.HostInfo{
		Hostname:     "E2E-TEST-NODE",
		OS:           "linux/amd64",
		PrivateIP:    "192.168.10.50",
		HardwareUUID: "11111111-2222-3333-4444-555555555555",
	}

	// 4. Execute enrollment network call
	enrollResp, err := enrollClient.EnrollEndpoint(expectedToken, hostInfo)
	if err != nil {
		t.Fatalf("enrollment dispatch failed: %v", err)
	}

	if enrollResp.ID != expectedAgentID || enrollResp.APIKey != expectedAPIKey {
		t.Fatalf("parsed credentials mismatch: got ID=%s, Key=%s", enrollResp.ID, enrollResp.APIKey)
	}

	// 5. Persist credentials locally
	agentCfg := &config.AgentConfig{
		ServerURL:    mockServer.URL,
		AgentID:      enrollResp.ID,
		APIKey:       enrollResp.APIKey,
		HardwareUUID: hostInfo.HardwareUUID,
	}

	if err := config.SaveConfig(agentCfg, configPath); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	// 6. Explicitly enforce OS-restricted file permissions
	if err := config.EnforceSecureStoragePermissions(configPath); err != nil {
		t.Fatalf("failed to enforce secure file permissions: %v", err)
	}

	// 7. Verify file exists and validate 0600 POSIX permissions on Linux
	fileInfo, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("config file missing from disk: %v", err)
	}

	currentPerm := fileInfo.Mode().Perm()
	if currentPerm != 0600 {
		t.Errorf("permission violation: expected 0600 (-rw-------), got %o", currentPerm)
	}
}