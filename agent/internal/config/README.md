# Agent Configuration & Secure Storage

## Overview
Agent configuration persistence subsystem managing cryptographic identities, UTF-8 BOM stripping, atomic filesystem commits, and operating-system-specific permission hardening (0600 on Linux, SYSTEM/Admin DACLs on Windows).

## Interface
- DefaultConfigDir() string [config.go:14]: Returns standard OS state path (/var/lib/rmmagent on Linux, %ProgramData%\rmmagent on Windows)
- ResolveConfigPath(explicitPath string) string [config.go:27]: Resolves active config file path from explicit flag, system path, or executable directory
- LoadConfig(path string) (*AgentConfig, error) [config.go:65]: Reads, strips UTF-8 BOM, and unmarshals JSON agent configuration
- SaveConfig(cfg *AgentConfig, targetPath string) error [config.go:89]: Atomically writes configuration via temporary file and enforces restricted permissions
- EnforceSecureStoragePermissions(path string) error [permissions.go:5]: Dispatches to OS-specific permission enforcement
- AgentConfig struct [config.go:48]: Persistent agent configuration holding credentials, server URL, hardware UUID, and verification keys

## Invariants
- Agent configuration must contain non-empty AgentID and APIKey fields [config.go:81-83]
- Configuration persistence writes to a temporary file before atomic renaming to prevent partial write corruption [config.go:103-117]
- File permissions are strictly locked down to 0600 on Linux and protected DACLs granting exclusive access to SYSTEM and Builtin Administrators on Windows [permissions_linux.go:11-22, permissions_windows.go:14-46]

## Side Effects
- File System: Creates state directories, writes temporary config files, and atomically replaces config.json
- OS Security: Mutates filesystem permissions and Windows NTFS security descriptors via Win32 SetNamedSecurityInfo or chmod

## Verification
- Run: `cd agent && go test -v ./internal/...`
