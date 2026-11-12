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
	"sync"
	"time"
)

const (
	// MaxClockSkewSec defines the maximum tolerated clock drift (5 minutes) between control plane and agent.
	MaxClockSkewSec int64 = 300
	// DefaultReplayCacheCapacity bounds the in-memory replay protection cache.
	DefaultReplayCacheCapacity = 4096
)

var (
	// ErrMissingPublicKey indicates the agent does not have a valid 32-byte Ed25519 verification key loaded.
	ErrMissingPublicKey = errors.New("missing or invalid Ed25519 verification public key")
	// ErrUnsignedPayload indicates a task/script or terminal frame arrived without an Ed25519 digital signature.
	ErrUnsignedPayload = errors.New("unsigned C2 frame rejected: missing Ed25519 signature")
	// ErrDigestMismatch indicates the recomputed SHA-256 payload digest does not match the frame's payload_sha256.
	ErrDigestMismatch = errors.New("tampered C2 frame rejected: SHA-256 payload digest mismatch")
	// ErrInvalidSignature indicates the Ed25519 signature is malformed or failed cryptographic verification.
	ErrInvalidSignature = errors.New("tampered or forged C2 frame rejected: Ed25519 signature verification failed")
	// ErrAgentMismatch indicates a signed C2 frame was addressed to a different target agent_id.
	ErrAgentMismatch = errors.New("cross-agent replay rejected: target agent_id mismatch")
	// ErrExpiredPayload indicates a signed C2 frame has an expired or future-dated timestamp.
	ErrExpiredPayload = errors.New("expired or out-of-window C2 frame rejected: timestamp outside validity window")
	// ErrReplayedPayload indicates a signed C2 frame reuses a previously executed task_id or cryptographic nonce.
	ErrReplayedPayload = errors.New("capture-replay attack rejected: nonce or task_id already executed")
	// ErrKeyFingerprintMismatch indicates a fetched server public key does not match the pinned SHA-256 fingerprint.
	ErrKeyFingerprintMismatch = errors.New("public key verification failed: SHA-256 fingerprint mismatch")
)

// TaskScope binds a task dispatch frame to a specific recipient agent, validity window, and anti-replay nonce.
type TaskScope struct {
	AgentID          string
	ExpectedAgentID  string
	IssuedAt         int64
	ExpiresAt        int64
	Nonce            string
	EnforceFreshness bool
	ReplayCache      *ReplayCache
}

// ReplayCache provides a thread-safe bounded cache of seen nonces and task IDs to prevent capture-replay attacks.
type ReplayCache struct {
	mu       sync.Mutex
	entries  map[string]int64
	capacity int
}

// NewReplayCache initializes a bounded anti-replay cache.
func NewReplayCache(capacity int) *ReplayCache {
	if capacity <= 0 {
		capacity = DefaultReplayCacheCapacity
	}
	return &ReplayCache{
		entries:  make(map[string]int64, capacity),
		capacity: capacity,
	}
}

// CheckAndRecord returns ErrReplayedPayload if key has already been recorded within its validity window,
// otherwise records key until expiresAt and returns nil.
func (rc *ReplayCache) CheckAndRecord(key string, expiresAt int64) error {
	if rc == nil || key == "" {
		return nil
	}

	now := time.Now().Unix()
	if expiresAt <= now {
		expiresAt = now + MaxClockSkewSec
	}

	rc.mu.Lock()
	defer rc.mu.Unlock()

	if exp, exists := rc.entries[key]; exists && exp >= now {
		return ErrReplayedPayload
	}

	if len(rc.entries) >= rc.capacity {
		for k, exp := range rc.entries {
			if exp < now {
				delete(rc.entries, k)
			}
		}
		if len(rc.entries) >= rc.capacity {
			for k := range rc.entries {
				delete(rc.entries, k)
				break
			}
		}
	}

	rc.entries[key] = expiresAt
	return nil
}

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

// ComputePublicKeyFingerprint returns the lowercase hex-encoded SHA-256 fingerprint of a parsed Ed25519 public key.
func ComputePublicKeyFingerprint(pubKey ed25519.PublicKey) string {
	sum := sha256.Sum256(pubKey)
	return hex.EncodeToString(sum[:])
}

// VerifyPublicKeyFingerprint validates that keyMaterial parses to a valid Ed25519 public key whose
// SHA-256 fingerprint matches expectedFingerprintHex in constant time.
func VerifyPublicKeyFingerprint(keyMaterial string, expectedFingerprintHex string) error {
	pubKey, err := ParseEd25519PublicKey(keyMaterial)
	if err != nil {
		return err
	}
	cleanExpected := strings.ToLower(strings.TrimSpace(expectedFingerprintHex))
	if cleanExpected == "" {
		return ErrKeyFingerprintMismatch
	}
	actual := ComputePublicKeyFingerprint(pubKey)
	if subtle.ConstantTimeCompare([]byte(actual), []byte(cleanExpected)) != 1 {
		return fmt.Errorf("%w: expected %s, got %s", ErrKeyFingerprintMismatch, cleanExpected, actual)
	}
	return nil
}

func hasScopeBinding(s TaskScope) bool {
	return strings.TrimSpace(s.AgentID) != "" ||
		strings.TrimSpace(s.Nonce) != "" ||
		s.IssuedAt != 0 ||
		s.ExpiresAt != 0
}

// BuildCanonicalTaskPayload constructs the deterministic byte slice signed by the FastAPI control plane.
// When TaskScope binding fields are present, it produces:
// "<agent_id>:<task_id>:<issued_at>:<expires_at>:<nonce>:<timeout_sec>:<command>".
func BuildCanonicalTaskPayload(taskID string, command string, timeoutSec int, scope ...TaskScope) []byte {
	normTask := strings.ToLower(strings.TrimSpace(taskID))
	if len(scope) > 0 && hasScopeBinding(scope[0]) {
		s := scope[0]
		normAgent := strings.ToLower(strings.TrimSpace(s.AgentID))
		normNonce := strings.TrimSpace(s.Nonce)
		return []byte(fmt.Sprintf(
			"%s:%s:%d:%d:%s:%d:%s",
			normAgent,
			normTask,
			s.IssuedAt,
			s.ExpiresAt,
			normNonce,
			timeoutSec,
			command,
		))
	}
	return []byte(fmt.Sprintf("%s:%d:%s", normTask, timeoutSec, command))
}

// BuildCanonicalTermInPayload constructs the domain-separated deterministic byte slice for signed PTY input:
// "term_in:<agent_id>:<issued_at>:<expires_at>:<nonce>:<payload>".
func BuildCanonicalTermInPayload(agentID string, issuedAt int64, expiresAt int64, nonce string, payload string) []byte {
	normAgent := strings.ToLower(strings.TrimSpace(agentID))
	normNonce := strings.TrimSpace(nonce)
	return []byte(fmt.Sprintf("term_in:%s:%d:%d:%s:%s", normAgent, issuedAt, expiresAt, normNonce, payload))
}

// ComputePayloadDigest returns the lowercase hex-encoded SHA-256 digest of data.
func ComputePayloadDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ComputeTaskDigest returns the lowercase hex-encoded SHA-256 digest of the canonical task payload.
func ComputeTaskDigest(taskID string, command string, timeoutSec int, scope ...TaskScope) string {
	return ComputePayloadDigest(BuildCanonicalTaskPayload(taskID, command, timeoutSec, scope...))
}

// ComputeTermInDigest returns the lowercase hex-encoded SHA-256 digest of the canonical terminal input payload.
func ComputeTermInDigest(agentID string, issuedAt int64, expiresAt int64, nonce string, payload string) string {
	return ComputePayloadDigest(BuildCanonicalTermInPayload(agentID, issuedAt, expiresAt, nonce, payload))
}

func validateScopeAndFreshness(s TaskScope) error {
	if s.ExpectedAgentID != "" {
		normActual := strings.ToLower(strings.TrimSpace(s.AgentID))
		normExpected := strings.ToLower(strings.TrimSpace(s.ExpectedAgentID))
		if normActual == "" || subtle.ConstantTimeCompare([]byte(normActual), []byte(normExpected)) != 1 {
			return ErrAgentMismatch
		}
	}

	if s.EnforceFreshness || s.IssuedAt != 0 || s.ExpiresAt != 0 {
		now := time.Now().Unix()
		if s.IssuedAt <= 0 || s.ExpiresAt <= 0 || s.ExpiresAt < s.IssuedAt {
			return ErrExpiredPayload
		}
		if s.IssuedAt > now+MaxClockSkewSec || now > s.ExpiresAt+MaxClockSkewSec {
			return ErrExpiredPayload
		}
		if strings.TrimSpace(s.Nonce) == "" {
			return ErrInvalidSignature
		}
	}

	return nil
}

// VerifyTaskDispatch verifies the target agent binding, timestamp freshness, SHA-256 payload digest,
// Ed25519 digital signature, and anti-replay cache before allowing script execution.
func VerifyTaskDispatch(
	pubKey ed25519.PublicKey,
	taskID string,
	command string,
	timeoutSec int,
	payloadSHA256 string,
	signatureB64 string,
	scope ...TaskScope,
) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return ErrMissingPublicKey
	}

	cleanSig := strings.TrimSpace(signatureB64)
	if cleanSig == "" {
		return ErrUnsignedPayload
	}

	if len(scope) > 0 {
		if err := validateScopeAndFreshness(scope[0]); err != nil {
			return err
		}
	}

	canonical := BuildCanonicalTaskPayload(taskID, command, timeoutSec, scope...)
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

	if len(scope) > 0 && scope[0].ReplayCache != nil {
		s := scope[0]
		normTask := strings.ToLower(strings.TrimSpace(taskID))
		normNonce := strings.TrimSpace(s.Nonce)
		if normTask != "" {
			if err := s.ReplayCache.CheckAndRecord("task:"+normTask, s.ExpiresAt); err != nil {
				return err
			}
		}
		if normNonce != "" {
			if err := s.ReplayCache.CheckAndRecord("nonce:"+normNonce, s.ExpiresAt); err != nil {
				return err
			}
		}
	}

	return nil
}

// VerifyTermIn verifies the target agent binding, timestamp freshness, SHA-256 digest, Ed25519 signature,
// and anti-replay nonce of an interactive terminal input frame (`term_in`).
func VerifyTermIn(
	pubKey ed25519.PublicKey,
	payload string,
	payloadSHA256 string,
	signatureB64 string,
	scope TaskScope,
) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return ErrMissingPublicKey
	}

	cleanSig := strings.TrimSpace(signatureB64)
	if cleanSig == "" {
		return ErrUnsignedPayload
	}

	scope.EnforceFreshness = true
	if err := validateScopeAndFreshness(scope); err != nil {
		return err
	}

	canonical := BuildCanonicalTermInPayload(scope.AgentID, scope.IssuedAt, scope.ExpiresAt, scope.Nonce, payload)
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

	if scope.ReplayCache != nil {
		normNonce := strings.TrimSpace(scope.Nonce)
		if err := scope.ReplayCache.CheckAndRecord("term_nonce:"+normNonce, scope.ExpiresAt); err != nil {
			return err
		}
	}

	return nil
}
