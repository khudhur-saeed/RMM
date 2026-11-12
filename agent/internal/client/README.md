# HTTPS Enrollment Client

## Overview
HTTPS enrollment client enforcing TLS 1.3, optional custom Root CA pinning, mTLS client certificates, and leaf/SPKI SHA-256 certificate pinning for endpoint onboarding and public key retrieval.

## Interface
- NewEnrollmentClient(serverURL string, caCertPath string, timeout time.Duration) (*EnrollmentClient, error) [enroll.go:76]: Creates HTTPS client enforcing TLS 1.3 and optional Root CA pool
- (*EnrollmentClient) ConfigureTLS(clientCertPath, clientKeyPath, certPinSHA256 string) error [enroll.go:118]: Applies mTLS client keypair and leaf/SPKI SHA-256 certificate pinning
- (*EnrollmentClient) EnrollEndpoint(token string, host *system.HostInfo) (*EnrollmentResponse, error) [enroll.go:165]: Submits host telemetry and token to /api/v1/enroll
- (*EnrollmentClient) FetchServerPublicKey() (*PublicKeyResponse, error) [enroll.go:211]: Retrieves active Ed25519 verification public key from /api/v1/keys/public
- EnrollmentPayload struct [enroll.go:24]: Schema matching FastAPI AgentEnroll
- EnrollmentResponse struct [enroll.go:33]: Schema matching FastAPI AgentEnrollResponse
- PublicKeyResponse struct [enroll.go:47]: Schema matching FastAPI PublicKeyRead
- EnrollmentClient struct [enroll.go:55]: HTTP client wrapper

## Invariants
- Plaintext HTTP transport is strictly rejected for all non-loopback destinations [enroll.go:82-84]
- TLS 1.3 is enforced as the minimum allowable protocol version [enroll.go:87]
- Certificate pins must be 64-character hex digests and are verified in constant time against leaf DER and SPKI hashes [enroll.go:136-159]

## Side Effects
- Network: Sends outbound HTTPS POST requests to /api/v1/enroll and HTTPS GET requests to /api/v1/keys/public
- File System: Reads custom Root CA certificates and mTLS keypairs from disk

## Verification
- Run: `cd agent && go test -v ./internal/client/...`
