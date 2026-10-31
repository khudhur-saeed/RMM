package authmon

import (
	"bufio"
	"io"
	"os"
)

// Default paths for Linux authentication logs across distributions.
var candidateAuthLogs = []string{
	"/var/log/auth.log", // Debian / Ubuntu
	"/var/log/secure",   // RHEL / CentOS / Rocky Linux
}

// Watcher manages incremental tailing and rotation detection for authentication logs.
type Watcher struct {
	logPath    string
	lastOffset int64
}

// NewWatcher detects the active OS authentication log file and initializes state.
func NewWatcher() *Watcher {
	activePath := ""
	for _, path := range candidateAuthLogs {
		if _, err := os.Stat(path); err == nil {
			activePath = path
			break
		}
	}

	return &Watcher{
		logPath:    activePath,
		lastOffset: 0,
	}
}

// ReadNewEvents inspects the log file from the last known offset and parses emerging security events.
func (w *Watcher) ReadNewEvents() ([]AuthEvent, error) {
	if w.logPath == "" {
		return []AuthEvent{}, nil
	}

	info, err := os.Stat(w.logPath)
	if err != nil {
		return nil, err
	}

	// Detect log rotation: if current file size is less than previous offset, reset to start
	if info.Size() < w.lastOffset {
		w.lastOffset = 0
	}

	file, err := os.Open(w.logPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.Seek(w.lastOffset, io.SeekStart); err != nil {
		return nil, err
	}

	var events []AuthEvent
	reader := bufio.NewReader(file)
	currentOffset := w.lastOffset

	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			currentOffset += int64(len(line))
			if event, matched := ParseAuthLine(line); matched {
				events = append(events, *event)
			}
		}

		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return events, readErr
		}
	}

	w.lastOffset = currentOffset
	return events, nil
}