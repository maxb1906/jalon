//go:build linux

package probe

import (
	"context"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/maxb1906/jalon/internal/model"
)

func newICMPProber(priv model.Privileges, v6 bool) (hopProber, string, error) {
	if priv.Admin || priv.CapNetRaw {
		network, laddr := "ip4:icmp", "0.0.0.0"
		if v6 {
			network, laddr = "ip6:ipv6-icmp", "::"
		}
		l, err := newRawListener(network, laddr)
		if err == nil {
			return l, "raw", nil
		}
	}
	if priv.UnprivPing {
		return &pingSock{v6: v6}, "dgram", nil
	}
	return nil, "", errNoICMP
}

func newTCPICMPListener(priv model.Privileges, v6 bool) (*rawListener, error) {
	if !(priv.Admin || priv.CapNetRaw) {
		return nil, errNoICMP
	}
	if v6 {
		return newRawListener("ip6:ipv6-icmp", "::")
	}
	return newRawListener("ip4:icmp", "0.0.0.0")
}

// pingSock utilise les sockets ICMP non privilégiées de Linux
// (net.ipv4.ping_group_range). Les erreurs ICMP (TTL expiré, injoignable)
// arrivent dans la file d'erreurs de la socket (IP_RECVERR).
type pingSock struct {
	v6  bool
	seq atomic.Uint32
}

func (p *pingSock) Close() error { return nil }

func (p *pingSock) Probe(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) reply {
	fam, proto := unix.AF_INET, unix.IPPROTO_ICMP
	if p.v6 {
		fam, proto = unix.AF_INET6, unix.IPPROTO_ICMPV6
	}
	fd, err := unix.Socket(fam, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return reply{kind: rTimeout}
	}
	defer unix.Close(fd)
	if p.v6 {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVERR, 1)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_RECVHOPLIMIT, 1)
	} else {
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVERR, 1)
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_RECVTTL, 1)
	}
	seq := int(p.seq.Add(1)+uint32(rand.IntN(1000))) & 0xffff
	var typ icmp.Type = ipv4.ICMPTypeEcho
	var sa unix.Sockaddr
	if p.v6 {
		typ = ipv6.ICMPTypeEchoRequest
		sa = &unix.SockaddrInet6{Addr: dst.As16()}
	} else {
		sa = &unix.SockaddrInet4{Addr: dst.As4()}
	}
	b, _ := (&icmp.Message{Type: typ, Body: &icmp.Echo{ID: 0, Seq: seq, Data: []byte("jalon-probe-0123456789")}}).Marshal(nil)
	start := time.Now()
	if err := unix.Sendto(fd, b, 0, sa); err != nil {
		return reply{kind: rTimeout}
	}
	deadline := start.Add(timeout)
	buf := make([]byte, 1500)
	oob := make([]byte, 512)
	for {
		if ctx.Err() != nil {
			return reply{kind: rTimeout}
		}
		left := time.Until(deadline)
		if left <= 0 {
			return reply{kind: rTimeout}
		}
		wait := min(left, 100*time.Millisecond)
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLERR}}
		n, err := unix.Poll(fds, int(wait/time.Millisecond)+1)
		if err != nil && err != unix.EINTR {
			return reply{kind: rTimeout}
		}
		if n == 0 {
			continue
		}
		if fds[0].Revents&unix.POLLERR != 0 {
			if r, ok := p.readErrQueue(fd, buf, oob, seq); ok {
				r.rtt = time.Since(start)
				return r
			}
			continue
		}
		if fds[0].Revents&unix.POLLIN != 0 {
			nn, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, 0)
			if err != nil {
				continue
			}
			pr := 1
			if p.v6 {
				pr = 58
			}
			m, err := icmp.ParseMessage(pr, buf[:nn])
			if err != nil {
				continue
			}
			e, ok := m.Body.(*icmp.Echo)
			if !ok || e.Seq != seq {
				continue
			}
			return reply{kind: rReached, from: dst, rtt: time.Since(start), ttl: cmsgTTL(oob[:oobn], p.v6)}
		}
	}
}

func cmsgTTL(oob []byte, v6 bool) int {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return 0
	}
	for _, m := range msgs {
		if (!v6 && m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_TTL) ||
			(v6 && m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_HOPLIMIT) {
			if len(m.Data) >= 4 {
				return int(binary.NativeEndian.Uint32(m.Data[:4]))
			}
		}
	}
	return 0
}

// readErrQueue lit la file d'erreurs (MSG_ERRQUEUE) : sock_extended_err
// suivi de l'adresse de l'émetteur du message ICMP.
func (p *pingSock) readErrQueue(fd int, buf, oob []byte, seq int) (reply, bool) {
	nn, oobn, _, _, err := unix.Recvmsg(fd, buf, oob, unix.MSG_ERRQUEUE)
	if err != nil {
		return reply{}, false
	}
	// Le datagramme renvoyé est notre écho d'origine : vérifier le seq.
	if nn >= 8 && int(binary.BigEndian.Uint16(buf[6:8])) != seq {
		return reply{}, false
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return reply{}, false
	}
	var r reply
	found := false
	for _, m := range msgs {
		isErr := (!p.v6 && m.Header.Level == unix.IPPROTO_IP && m.Header.Type == unix.IP_RECVERR) ||
			(p.v6 && m.Header.Level == unix.IPPROTO_IPV6 && m.Header.Type == unix.IPV6_RECVERR)
		if isErr {
			if len(m.Data) < 16 {
				continue
			}
			origin, typ := m.Data[4], m.Data[5]
			off := m.Data[16:]
			switch {
			case !p.v6 && origin == unix.SO_EE_ORIGIN_ICMP && len(off) >= 8:
				r.from = netip.AddrFrom4([4]byte(off[4:8]))
				switch typ {
				case 11:
					r.kind = rTimeExceeded
				case 3:
					r.kind = rUnreachable
				default:
					continue
				}
				found = true
			case p.v6 && origin == unix.SO_EE_ORIGIN_ICMP6 && len(off) >= 24:
				r.from = netip.AddrFrom16([16]byte(off[8:24])).Unmap()
				switch typ {
				case 3:
					r.kind = rTimeExceeded
				case 1:
					r.kind = rUnreachable
				default:
					continue
				}
				found = true
			}
		}
		if t := cmsgTTL(oob[:oobn], p.v6); t > 0 {
			r.ttl = t
		}
	}
	return r, found
}
