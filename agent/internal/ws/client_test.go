package ws

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	agentCrypto "tactical-rmm/agent/internal/crypto"
)

func TestHandleTaskDispatch_DropsUnsignedTamperedAndReplayedScripts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}

	targetAgentID := "11111111-2222-3333-4444-555555555555"
	otherAgentID := "99999999-8888-7777-6666-555555555555"

	client, err := NewClient(Config{
		ServerURL:        "http://127.0.0.1:8000",
		AgentID:          targetAgentID,
		APIKey:           "rmm_sec_test",
		SigningPublicKey: base64.StdEncoding.EncodeToString(pub),
	})
	if err != nil {
		t.Fatalf("failed to create ws client: %v", err)
	}

	now := time.Now().Unix()

	// 1. Unsigned task frame -> must be dropped before execution (no frames emitted on outboundChan)
	unsignedTask := TaskDispatchFrame{
		Type:       "task_dispatch",
		TaskID:     "aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0001",
		AgentID:    targetAgentID,
		IssuedAt:   now,
		ExpiresAt:  now + 120,
		Nonce:      "nonce_unsigned_0001",
		Command:    "echo SHOULD_NOT_EXECUTE_UNSIGNED",
		TimeoutSec: 10,
	}
	client.handleTaskDispatch(unsignedTask)
	if len(client.outboundChan) != 0 {
		t.Fatalf("expected 0 outbound frames for dropped unsigned script, got %d", len(client.outboundChan))
	}

	// 2. Tampered task frame -> must be dropped before execution (no frames emitted on outboundChan)
	legitCmd := "echo LEGIT_COMMAND"
	taskID2 := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0002"
	scope2 := agentCrypto.TaskScope{
		AgentID:   targetAgentID,
		IssuedAt:  now,
		ExpiresAt: now + 120,
		Nonce:     "nonce_tampered_0002",
	}
	canonical2 := agentCrypto.BuildCanonicalTaskPayload(taskID2, legitCmd, 10, scope2)
	sig2 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical2))

	tamperedTask := TaskDispatchFrame{
		Type:          "task_dispatch",
		TaskID:        taskID2,
		AgentID:       targetAgentID,
		IssuedAt:      scope2.IssuedAt,
		ExpiresAt:     scope2.ExpiresAt,
		Nonce:         scope2.Nonce,
		Command:       "echo TAMPERED_MALICIOUS_COMMAND",
		TimeoutSec:    10,
		PayloadSHA256: agentCrypto.ComputeTaskDigest(taskID2, legitCmd, 10, scope2),
		Signature:     sig2,
	}
	client.handleTaskDispatch(tamperedTask)
	if len(client.outboundChan) != 0 {
		t.Fatalf("expected 0 outbound frames for dropped tampered script, got %d", len(client.outboundChan))
	}

	// 3. Cross-agent replay -> signed for otherAgentID, replayed to targetAgentID -> must be dropped
	taskIDCross := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0099"
	scopeCross := agentCrypto.TaskScope{
		AgentID:   otherAgentID,
		IssuedAt:  now,
		ExpiresAt: now + 120,
		Nonce:     "nonce_cross_agent_0099",
	}
	canonicalCross := agentCrypto.BuildCanonicalTaskPayload(taskIDCross, legitCmd, 10, scopeCross)
	sigCross := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonicalCross))

	crossAgentTask := TaskDispatchFrame{
		Type:          "task_dispatch",
		TaskID:        taskIDCross,
		AgentID:       otherAgentID,
		IssuedAt:      scopeCross.IssuedAt,
		ExpiresAt:     scopeCross.ExpiresAt,
		Nonce:         scopeCross.Nonce,
		Command:       legitCmd,
		TimeoutSec:    10,
		PayloadSHA256: agentCrypto.ComputeTaskDigest(taskIDCross, legitCmd, 10, scopeCross),
		Signature:     sigCross,
	}
	client.handleTaskDispatch(crossAgentTask)
	if len(client.outboundChan) != 0 {
		t.Fatalf("expected 0 outbound frames for cross-agent replayed task, got %d", len(client.outboundChan))
	}

	// 4. Validly signed task frame -> verified and executed, emitting stdout + exit frames
	taskID3 := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0003"
	signedCmd := "echo VERIFIED_OK"
	scope3 := agentCrypto.TaskScope{
		AgentID:   targetAgentID,
		IssuedAt:  now,
		ExpiresAt: now + 120,
		Nonce:     "nonce_valid_0003",
	}
	canonical3 := agentCrypto.BuildCanonicalTaskPayload(taskID3, signedCmd, 10, scope3)
	sig3 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical3))

	validTask := TaskDispatchFrame{
		Type:          "task_dispatch",
		TaskID:        taskID3,
		AgentID:       targetAgentID,
		IssuedAt:      scope3.IssuedAt,
		ExpiresAt:     scope3.ExpiresAt,
		Nonce:         scope3.Nonce,
		Command:       signedCmd,
		TimeoutSec:    10,
		PayloadSHA256: agentCrypto.ComputeTaskDigest(taskID3, signedCmd, 10, scope3),
		Signature:     sig3,
	}
	client.handleTaskDispatch(validTask)

	if len(client.outboundChan) == 0 {
		t.Fatalf("expected signed task to execute and emit output frames")
	}

	var sawExit bool
	for len(client.outboundChan) > 0 {
		raw := <-client.outboundChan
		var env map[string]any
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("failed to unmarshal outbound frame: %v", err)
		}
		if env["type"] == "task_exit" && env["task_id"] == taskID3 {
			sawExit = true
			if int(env["exit_code"].(float64)) != 0 {
				t.Errorf("expected exit_code 0 for verified task, got %v", env["exit_code"])
			}
		}
	}
	if !sawExit {
		t.Errorf("expected task_exit frame for verified signed task")
	}

	// 5. Replaying the same validTask a second time must be rejected by the anti-replay cache
	client.handleTaskDispatch(validTask)
	if len(client.outboundChan) != 0 {
		t.Fatalf("expected 0 outbound frames for replayed task dispatch, got %d", len(client.outboundChan))
	}

	// 6. Unsigned term_in frame must be rejected without allocating a PTY session
	client.handleSignedTerminalInput(TermInFrame{
		Type:    "term_in",
		AgentID: targetAgentID,
		Payload: "whoami\n",
	})
	if client.termSession != nil {
		t.Fatalf("expected unsigned term_in frame to be dropped before PTY allocation")
	}
}
