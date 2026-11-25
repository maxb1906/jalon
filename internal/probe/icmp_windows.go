//go:build windows

package probe

import (
	"context"
	"errors"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/maxb1906/jalon/internal/model"
)

var (
	iphlpapi       = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose  = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSend   = iphlpapi.NewProc("IcmpSendEcho")
)

// ipOptionInformation reprend IP_OPTION_INFORMATION.
type ipOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpEchoReply reprend ICMP_ECHO_REPLY.
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

const (
	ipSuccess           = 0
	ipDestNetUnreach    = 11002
	ipDestHostUnreach   = 11003
	ipDestProtUnreach   = 11004
	ipDestPortUnreach   = 11005
	ipReqTimedOut       = 11010
	ipTTLExpiredTransit = 11013
	ipTTLExpiredReassem = 11014
)

// winICMP utilise IcmpSendEcho (iphlpapi), disponible sans droits.
type winICMP struct{}

func newICMPProber(priv model.Privileges, v6 bool) (hopProber, string, error) {
	if v6 {
		return nil, "", errors.New("traceroute ICMPv6 non pris en charge sous Windows")
	}
	if err := procIcmpSend.Find(); err != nil {
		return nil, "", err
	}
	return winICMP{}, "IcmpSendEcho", nil
}

func (winICMP) Close() error { return nil }

func (winICMP) Probe(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) reply {
	h, _, _ := procIcmpCreate.Call()
	if h == 0 || h == uintptr(windows.InvalidHandle) {
		return reply{kind: rTimeout}
	}
	defer procIcmpClose.Call(h)
	a := dst.As4()
	addr := *(*uint32)(unsafe.Pointer(&a[0]))
	data := []byte("jalon-probe-0123456789")
	opt := ipOptionInformation{Ttl: uint8(ttl)}
	buf := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+len(data)+8+64)
	start := time.Now()
	n, _, _ := procIcmpSend.Call(h, uintptr(addr),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)),
		uintptr(unsafe.Pointer(&opt)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
		uintptr(timeout/time.Millisecond))
	el := time.Since(start)
	if n == 0 {
		return reply{kind: rTimeout}
	}
	rep := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
	var b [4]byte
	*(*uint32)(unsafe.Pointer(&b[0])) = rep.Address
	from := netip.AddrFrom4(b)
	rtt := time.Duration(rep.RoundTripTime) * time.Millisecond
	if rtt == 0 {
		rtt = el
	}
	r := reply{from: from, rtt: rtt, ttl: int(rep.Options.Ttl)}
	switch rep.Status {
	case ipSuccess:
		r.kind = rReached
	case ipTTLExpiredTransit, ipTTLExpiredReassem:
		r.kind = rTimeExceeded
	case ipDestNetUnreach, ipDestHostUnreach, ipDestProtUnreach, ipDestPortUnreach:
		r.kind = rUnreachable
	default:
		return reply{kind: rTimeout}
	}
	return r
}

// Sous Windows (administrateur), une socket raw ICMP reçoit les
// « TTL expiré » provoqués par nos SYN TCP. Npcap n'est pas nécessaire pour
// cette méthode ; sa présence est seulement signalée dans le rapport.
func newTCPICMPListener(priv model.Privileges, v6 bool) (*rawListener, error) {
	if !priv.Admin {
		return nil, errNoICMP
	}
	if v6 {
		return nil, errors.New("traceroute TCP IPv6 non pris en charge sous Windows")
	}
	laddr := "0.0.0.0"
	if priv.LocalIPv4 != "" {
		laddr = priv.LocalIPv4
	}
	return newRawListener("ip4:icmp", laddr)
}
