package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrMissingPublicKey indicates the agent does not have a valid 32-byte Ed25519 verification key loaded.
	ErrMissingPublicKey = errors.New("missing or invalid Ed25519 verification public key")
	// ErrUnsignedPayload indicates a task/script dispatch frame arrived without an Ed25519 digital signature.
	ErrUnsignedPayload = errors.New("unsigned script/task dispatch rejected: missing Ed25519 signature")
	// ErrDigestMismatch indicates the recomputed SHA-256 payload digest does not match the frame's payload_sha256.
	ErrDigestMismatch = errors.New("tampered script/task dispatch rejected: SHA-256 payload digest mismatch")
	// ErrInvalidSignature indicates the Ed25519 signature is malformed or failed cryptographic verification.
	ErrInvalidSignature = errors.New("tampered or forged script/task dispatch rejected: Ed25519 signature verification failed")
)

// ParseEd25519PublicKey parses an Ed25519 public key from either a SubjectPublicKeyInfo PEM block
// or a standard Base64-encoded 32-byte raw public key string.
func ParseEd25519PublicKey(keyMaterial string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(keyMaterial)
	if trimmed == "" {
		return nil, ErrMissingPublicKey
	}

	if strings.HasPrefix(trimmed, "-----BEGIN") {
		block, _ := pem.Decode([]byte(trimmed))
		if block == nil {
			return nil, errors.New("failed to decode PEM block for Ed25519 public key")
		}
		pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX Ed25519 public key: %w", err)
		}
		pubKey, ok := pubInterface.(ed25519.PublicKey)
		if !ok || len(pubKey) != ed25519.PublicKeySize {
			return nil, errors.New("PEM public key is not a valid Ed25519 key")
		}
		return pubKey, nil
	}

	rawBytes, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid Base64 Ed25519 public key encoding: %w", err)
	}
	if len(rawBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(rawBytes))
	}

	return ed25519.PublicKey(rawBytes), nil
}

// BuildCanonicalTaskPayload constructs the deterministic byte slice signed by the FastAPI control plane:
// "<task_id>:<timeout_sec>:<command>".
func BuildCanonicalTaskPayload(taskID string, command string, timeoutSec int) []byte {
	return []byte(fmt.Sprintf("%s:%d:%s", taskID, timeoutSec, command))
}

// ComputePayloadDigest returns the lowercase hex-encoded SHA-256 digest of data.
func ComputePayloadDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ComputeTaskDigest returns the lowercase hex-encoded SHA-256 digest of the canonical task payload.
func ComputeTaskDigest(taskID string, command string, timeoutSec int) string {
	return ComputePayloadDigest(BuildCanonicalTaskPayload(taskID, command, timeoutSec))
}

// VerifyTaskDispatch verifies both the optional SHA-256 payload digest and the mandatory
// Ed25519 digital signature over the canonical task payload before allowing script execution.
func VerifyTaskDispatch(
	pubKey ed25519.PublicKey,
	taskID string,
	command string,
	timeoutSec int,
	payloadSHA256 string,
	signatureB64 string,
) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return ErrMissingPublicKey
	}

	cleanSig := strings.TrimSpace(signatureB64)
	if cleanSig == "" {
		return ErrUnsignedPayload
	}

	canonical := BuildCanonicalTaskPayload(taskID, command, timeoutSec)
	expectedDigest := ComputePayloadDigest(canonical)

	cleanDigest := strings.ToLower(strings.TrimSpace(payloadSHA256))
	if cleanDigest != "" {
		if subtle.ConstantTimeCompare([]byte(cleanDigest), []byte(expectedDigest)) != 1 {
			return ErrDigestMismatch
		}
	}

	sigBytes, err := base64.StdEncoding.DecodeString(cleanSig)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}

	if !ed25519.Verify(pubKey, canonical, sigBytes) {
		return ErrInvalidSignature
	}

	return nil
}
