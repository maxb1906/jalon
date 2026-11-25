//go:build windows

package probe

import (
	"syscall"

	"golang.org/x/sys/windows"
)

func isRefused(e syscall.Errno) bool { return e == windows.WSAECONNREFUSED }
func isUnreachable(e syscall.Errno) bool {
	return e == windows.WSAEHOSTUNREACH || e == windows.WSAENETUNREACH || e == windows.WSAEADDRNOTAVAIL
}
func isTimedOut(e syscall.Errno) bool { return e == windows.WSAETIMEDOUT }
