package terminal

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"

	"github.com/creack/pty"
)

// Session manages an active interactive pseudoterminal attached to a shell.
type Session struct {
	cmd  *exec.Cmd
	ptmx *os.File
	once sync.Once
}

// OutboundMessage represents the JSON envelope pushed to the control plane.
type OutboundMessage struct {
	Type    string `json:"type"`
	Payload string `json:"payload"`
}

// NewSession spawns an interactive shell inside a newly allocated PTY.
func NewSession() (*Session, error) {
	cmd := exec.Command("/bin/bash", "-i")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}

	return &Session{
		cmd:  cmd,
		ptmx: ptmx,
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
					outboundChan <- payloadBytes
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
