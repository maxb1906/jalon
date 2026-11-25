//go:build darwin

package probe

import "github.com/maxb1906/jalon/internal/model"

// macOS autorise les sockets ICMP datagramme sans droits ; en root on
// utilise une socket raw, plus fiable pour recevoir les « TTL expiré ».
func newICMPProber(priv model.Privileges, v6 bool) (hopProber, string, error) {
	if priv.Admin {
		network, laddr := "ip4:icmp", "0.0.0.0"
		if v6 {
			network, laddr = "ip6:ipv6-icmp", "::"
		}
		if l, err := newRawListener(network, laddr); err == nil {
			return l, "raw", nil
		}
	}
	network, laddr := "udp4", "0.0.0.0"
	if v6 {
		network, laddr = "udp6", "::"
	}
	l, err := newRawListener(network, laddr)
	if err != nil {
		return nil, "", err
	}
	return l, "dgram", nil
}

func newTCPICMPListener(priv model.Privileges, v6 bool) (*rawListener, error) {
	if !priv.Admin {
		return nil, errNoICMP
	}
	if v6 {
		return newRawListener("ip6:ipv6-icmp", "::")
	}
	return newRawListener("ip4:icmp", "0.0.0.0")
}
