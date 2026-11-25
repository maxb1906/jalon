//go:build windows

package probe

import (
	"errors"

	"golang.org/x/sys/windows"
)

func setTTL(fd uintptr, ttl int, v6 bool) error {
	if v6 {
		return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_UNICAST_HOPS, ttl)
	}
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TTL, ttl)
}

func isAddrInUse(err error) bool { return errors.Is(err, windows.WSAEADDRINUSE) }
