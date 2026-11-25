//go:build !windows

package probe

import (
	"errors"
	"syscall"
)

func setTTL(fd uintptr, ttl int, v6 bool) error {
	if v6 {
		return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	}
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}

func isAddrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
