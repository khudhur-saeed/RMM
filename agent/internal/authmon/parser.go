package authmon

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// reSSHSuccess matches: Accepted password/publickey for <user> from <ip> port <port>
	reSSHSuccess = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)`)

	// reSSHFailed matches: Failed password for [invalid user ]<user> from <ip> port <port>
	reSSHFailed = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)

	// reSudoCommand matches: <user> : ... COMMAND=<command>
	reSudoCommand = regexp.MustCompile(`sudo:\s+(\S+)\s+:.*COMMAND=(.+)`)

	// reSudoFailed matches: pam_unix(sudo:auth): authentication failure; ... user=<user>
	reSudoFailed = regexp.MustCompile(`sudo:.*authentication failure.*user=(\S+)`)
)

// ParseAuthLine inspects a single log line from auth.log/secure and extracts security events.
func ParseAuthLine(line string) (*AuthEvent, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil, false
	}

	timestamp := time.Now().UTC().Format(time.RFC3339)

	// 1. Check SSH Login Success
	if matches := reSSHSuccess.FindStringSubmatch(trimmed); len(matches) == 4 {
		port, _ := strconv.Atoi(matches[3])
		return &AuthEvent{
			EventType:  AuthEventSSHSuccess,
			Timestamp:  timestamp,
			User:       matches[1],
			SourceIP:   matches[2],
			Port:       port,
			RawMessage: trimmed,
		}, true
	}

	// 2. Check SSH Login Failure (Brute Force Detection)
	if matches := reSSHFailed.FindStringSubmatch(trimmed); len(matches) == 4 {
		port, _ := strconv.Atoi(matches[3])
		return &AuthEvent{
			EventType:  AuthEventSSHFailed,
			Timestamp:  timestamp,
			User:       matches[1],
			SourceIP:   matches[2],
			Port:       port,
			RawMessage: trimmed,
		}, true
	}

	// 3. Check Sudo Privilege Execution
	if matches := reSudoCommand.FindStringSubmatch(trimmed); len(matches) == 3 {
		return &AuthEvent{
			EventType:  AuthEventSudoCommand,
			Timestamp:  timestamp,
			User:       matches[1],
			Command:    matches[2],
			RawMessage: trimmed,
		}, true
	}

	// 4. Check Sudo Authentication Failure
	if matches := reSudoFailed.FindStringSubmatch(trimmed); len(matches) == 2 {
		return &AuthEvent{
			EventType:  AuthEventSudoFailed,
			Timestamp:  timestamp,
			User:       matches[1],
			RawMessage: trimmed,
		}, true
	}

	return nil, false
}