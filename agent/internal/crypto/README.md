# Cryptographic Signature & Anti-Replay Engine

## Overview
Cryptographic engine providing Ed25519 digital signature validation, SHA-256 payload digest verification, canonical serialization, timestamp freshness bounds, and thread-safe anti-replay caching.

## Interface
- ParseEd25519PublicKey(keyMaterial string) (ed25519.PublicKey, error) [verifier.go:112]: Parses Ed25519 public key from SubjectPublicKeyInfo PEM block or Base64 string
- ComputePublicKeyFingerprint(pubKey ed25519.PublicKey) string [verifier.go:146]: Returns lowercase hex SHA-256 fingerprint of public key
- VerifyPublicKeyFingerprint(keyMaterial string, expectedFingerprintHex string) error [verifier.go:153]: Validates public key fingerprint in constant time
- BuildCanonicalTaskPayload(taskID string, command string, timeoutSec int, scope ...TaskScope) []byte [verifier.go:179]: Constructs deterministic canonical byte slice for task signing
- BuildCanonicalTermInPayload(agentID string, issuedAt int64, expiresAt int64, nonce string, payload string) []byte [verifier.go:201]: Constructs canonical byte slice for signed terminal input
- ComputePayloadDigest(data []byte) string [verifier.go:208]: Returns lowercase hex SHA-256 digest of arbitrary bytes
- ComputeTaskDigest(taskID string, command string, timeoutSec int, scope ...TaskScope) string [verifier.go:214]: Computes SHA-256 digest of canonical task payload
- ComputeTermInDigest(agentID string, issuedAt int64, expiresAt int64, nonce string, payload string) string [verifier.go:219]: Computes SHA-256 digest of canonical terminal input
- VerifyTaskDispatch(pubKey ed25519.PublicKey, taskID string, command string, timeoutSec int, payloadSHA256 string, signatureB64 string, scope ...TaskScope) error [verifier.go:250]: Verifies agent binding, freshness, payload digest, Ed25519 signature, and replay cache
- VerifyTermIn(pubKey ed25519.PublicKey, payload string, payloadSHA256 string, signatureB64 string, scope TaskScope) error [verifier.go:314]: Verifies PTY terminal input signature and freshness
- NewReplayCache(capacity int) *ReplayCache [verifier.go:63]: Initializes bounded in-memory anti-replay cache
- (*ReplayCache) CheckAndRecord(key string, expiresAt int64) error [verifier.go:75]: Records anti-replay key and rejects duplicate deliveries
- TaskScope struct [verifier.go:45]: Recipient binding, validity timestamps, and anti-replay nonce scope
- ReplayCache struct [verifier.go:56]: Thread-safe anti-replay cache

## Invariants
- Maximum clock drift tolerance is strictly bounded to 300 seconds (5 minutes) [verifier.go:20]
- All digest, fingerprint, and agent ID comparisons use constant-time matching (subtle.ConstantTimeCompare) to eliminate timing side channels [verifier.go:105, 112, 163, 227, 280, 340]
- Replay cache rejects previously executed task IDs and nonces within their validity window with ErrReplayedPayload [verifier.go:88-90, 298-306, 355-359]

## Side Effects
- Memory: Allocates and maintains synchronized in-memory anti-replay cache entries up to configured capacity (default 4096)

## Verification
- Run: `cd agent && go test -v ./internal/crypto/...`
