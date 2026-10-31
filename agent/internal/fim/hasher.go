package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// CalculateSHA256 streams file contents through a cryptographic hasher without allocating whole-file RAM buffers.
func CalculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("unable to open target file for hashing: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("streaming hash computation failed: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// CaptureFileMetadata inspects file stat attributes and computes its cryptographic signature.
func CaptureFileMetadata(filePath string) (*FileMetadata, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file metadata: %w", err)
	}

	hash, err := CalculateSHA256(filePath)
	if err != nil {
		return nil, err
	}

	return &FileMetadata{
		Path:        filePath,
		SHA256:      hash,
		Size:        info.Size(),
		Permissions: info.Mode().String(),
		ModTime:     info.ModTime().UTC().Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}
