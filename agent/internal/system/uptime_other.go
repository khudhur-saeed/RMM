//go:build !linux && !windows

package system

import "fmt"

func getSystemUptime() (uint64, error) {
	return 0, fmt.Errorf("uptime unsupported on this platform")
}
