//go:build linux

package system

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func getSystemUptime() (uint64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			uptimeFloat, err := strconv.ParseFloat(fields[0], 64)
			if err == nil {
				return uint64(uptimeFloat), nil
			}
		}
	}
	return 0, fmt.Errorf("failed to read /proc/uptime: %w", err)
}
