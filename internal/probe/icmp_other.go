//go:build !linux && !darwin && !windows

package probe

import "github.com/maxb1906/jalon/internal/model"

func newICMPProber(priv model.Privileges, v6 bool) (hopProber, string, error) {
	network, laddr := "ip4:icmp", "0.0.0.0"
	if v6 {
		network, laddr = "ip6:ipv6-icmp", "::"
	}
	l, err := newRawListener(network, laddr)
	if err != nil {
		return nil, "", err
	}
	return l, "raw", nil
}

func newTCPICMPListener(priv model.Privileges, v6 bool) (*rawListener, error) {
	if v6 {
		return newRawListener("ip6:ipv6-icmp", "::")
	}
	return newRawListener("ip4:icmp", "0.0.0.0")
}
