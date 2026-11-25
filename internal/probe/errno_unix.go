//go:build !windows

package probe

import "syscall"

func isRefused(e syscall.Errno) bool { return e == syscall.ECONNREFUSED }
func isUnreachable(e syscall.Errno) bool {
	return e == syscall.EHOSTUNREACH || e == syscall.ENETUNREACH || e == syscall.EADDRNOTAVAIL
}
func isTimedOut(e syscall.Errno) bool { return e == syscall.ETIMEDOUT }
