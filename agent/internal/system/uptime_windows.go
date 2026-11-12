//go:build windows

package system

import (
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64 = modKernel32.NewProc("GetTickCount64")
)

func getSystemUptime() (uint64, error) {
	r1, _, err := procGetTickCount64.Call()
	if r1 == 0 && err != windows.ERROR_SUCCESS && err != syscall.Errno(0) {
		return 0, err
	}
	return uint64(r1) / 1000, nil
}
