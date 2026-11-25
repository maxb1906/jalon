package probe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/maxb1906/jalon/internal/model"
)

// Issues d'une connexion TCP.
const (
	tcpConnected   = "connected"
	tcpRefused     = "refused"
	tcpTimeout     = "timeout"
	tcpUnreachable = "unreachable"
	tcpNoAddress   = "no_address"
	tcpNoLocal     = "no_local"
	tcpError       = "error"
)

// classifyDialErr distingue refus (RST), filtrage (timeout) et
// injoignabilité (ICMP / pas de route).
func classifyDialErr(err error) string {
	if err == nil {
		return tcpConnected
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return tcpTimeout
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch {
		case isRefused(errno):
			return tcpRefused
		case isUnreachable(errno):
			return tcpUnreachable
		case isTimedOut(errno):
			return tcpTimeout
		}
	}
	return tcpError
}

// hasGlobalV6 indique si le poste dispose d'une adresse IPv6 globale.
func hasGlobalV6(env *model.EnvResult) bool {
	return env != nil && env.LocalIPv6 != ""
}

// TCP mesure la connexion au port cible pour une famille d'adresses.
func TCP(ctx context.Context, cfg Config, family string, ips []string, port int) *model.TCPResult {
	start := time.Now()
	r := &model.TCPResult{Family: family, Port: port}
	defer r.Elapsed(start)
	if len(ips) == 0 {
		r.Outcome = tcpNoAddress
		if family == "ipv6" {
			r.Skip("tcp.no_aaaa")
		} else {
			r.Skip("tcp.no_a")
		}
		return r
	}
	r.IP = ips[0]
	if family == "ipv6" && !hasGlobalV6(cfg.Env) {
		r.Outcome = tcpNoLocal
		r.Skip("tcp.no_local_v6")
		return r
	}
	ctx, cancel := cfg.stepCtx(ctx)
	defer cancel()
	addr := net.JoinHostPort(r.IP, strconv.Itoa(port))
	t0 := time.Now()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	rtt := time.Since(t0)
	r.Outcome = classifyDialErr(err)
	if err != nil {
		r.Error = shortErr(err)
	} else {
		c.Close()
		r.RTTMs = model.Ms(rtt)
	}
	switch r.Outcome {
	case tcpConnected:
		r.Set(model.OK, "tcp.connected", r.IP, port, ms1(r.RTTMs))
	case tcpRefused:
		r.Set(model.Fail, "tcp.refused", r.IP, port)
	case tcpTimeout:
		r.Set(model.Fail, "tcp.timeout", r.IP, port, cfg.timeout().Round(time.Millisecond))
	case tcpUnreachable:
		r.Set(model.Fail, "tcp.unreachable", r.IP, port)
	default:
		r.Set(model.Fail, "tcp.error", r.IP, port, r.Error)
	}
	if len(ips) > 1 {
		r.AddNote(model.Info, "tcp.other_ips", len(ips)-1)
	}
	return r
}

// TCPAdjust ajuste les statuts IPv4/IPv6 l'un par rapport à l'autre :
// IPv6 annoncé mais cassé alors que l'IPv4 marche = avertissement.
func TCPAdjust(v4, v6 *model.TCPResult) {
	if v4 == nil || v6 == nil {
		return
	}
	if v4.Outcome == tcpConnected && v6.Status == model.Fail {
		v6.Status = model.Warn
		v6.AddNote(model.Warn, "tcp.v6_broken")
	}
	if v6.Outcome == tcpConnected && v4.Status == model.Fail {
		v4.Status = model.Warn
		v4.AddNote(model.Warn, "tcp.v4_broken")
	}
}

func ms1(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) }

// dialIP établit une connexion TCP vers ip:port.
func dialIP(ctx context.Context, ip string, port int) (net.Conn, time.Duration, error) {
	t0 := time.Now()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	return c, time.Since(t0), err
}

// family renvoie ipv4/ipv6 pour une adresse.
func family(ip string) string {
	if a, err := netip.ParseAddr(ip); err == nil && a.Is6() && !a.Is4In6() {
		return "ipv6"
	}
	return "ipv4"
}
