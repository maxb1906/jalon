package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/maxb1906/jalon/internal/model"
)

// Env collecte l'environnement local : interfaces, passerelle, DNS, proxy,
// droits disponibles et ping de la passerelle.
func Env(ctx context.Context, cfg Config) *model.EnvResult {
	start := time.Now()
	r := &model.EnvResult{OS: runtime.GOOS + "/" + runtime.GOARCH}
	r.Hostname, _ = os.Hostname()
	r.LocalIPv4 = defaultSource("udp4", "1.1.1.1:53")
	r.LocalIPv6 = defaultSource("udp6", "[2606:4700:4700::1111]:53")
	r.Ifaces = interfaces(r.LocalIPv4, r.LocalIPv6)
	r.Gateways = osGateways()
	r.DNSServers, r.DNSUpstream = osDNSServers()
	r.Proxies = envProxies()
	osProxies(r)
	osPrivileges(&r.Priv)
	r.Priv.LocalIPv4 = r.LocalIPv4
	finishPrivileges(&r.Priv)

	// WPAD : le nom « wpad » se résout-il sur le réseau local ?
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	if addrs, err := net.DefaultResolver.LookupHost(wctx, "wpad"); err == nil && len(addrs) > 0 {
		r.WPAD = addrs[0]
	}
	cancel()
	if r.PAC != "" {
		r.AddNote(model.Info, "env.pac", r.PAC, fetchPAC(ctx, r.PAC))
	}
	if r.WPAD != "" {
		r.AddNote(model.Info, "env.wpad", r.WPAD)
	}
	for _, p := range r.Proxies {
		r.AddNote(model.Info, "env.proxy", p.Source, p.Value)
	}
	if len(r.DNSUpstream) > 0 {
		r.AddNote(model.Info, "env.dns_upstream", strings.Join(r.DNSUpstream, ", "))
	}

	// Ping de la passerelle IPv4.
	if gw := firstV4(r.Gateways); gw.IsValid() {
		ps := &model.PingStat{Target: gw.String()}
		r.GatewayPing = ps
		if !r.Priv.ICMPTrace {
			ps.Error = "icmp"
		} else if p, _, err := newICMPProber(r.Priv, false); err != nil {
			ps.Error = err.Error()
		} else {
			pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			sent, recv, rtts, ttl := ping(pctx, p, gw, 3, time.Second)
			cancel()
			p.Close()
			fillPing(ps, sent, recv, rtts, ttl)
		}
	}

	// Statut et résumé.
	iface := ""
	for _, i := range r.Ifaces {
		if i.Default {
			iface = i.Name
		}
	}
	switch {
	case r.LocalIPv4 == "" && r.LocalIPv6 == "":
		r.Set(model.Fail, "env.no_network")
	case len(r.Gateways) == 0:
		r.Set(model.Warn, "env.no_gateway", iface, firstNonEmpty(r.LocalIPv4, r.LocalIPv6))
	default:
		r.Set(model.OK, "env.summary", iface, firstNonEmpty(r.LocalIPv4, r.LocalIPv6), strings.Join(r.Gateways, ", "))
		if ps := r.GatewayPing; ps != nil {
			switch {
			case ps.Error != "":
				r.AddNote(model.Info, "env.gw_ping_unavailable")
			case ps.Recv == 0:
				r.Status = model.Warn
				r.AddNote(model.Warn, "env.gw_ping_lost", ps.Target)
			default:
				r.AddNote(model.OK, "env.gw_ping", ps.Target, fmt.Sprintf("%.1f", ps.AvgMs), ps.Recv, ps.Sent)
			}
		}
	}
	if len(r.DNSServers) == 0 {
		r.AddNote(model.Warn, "env.no_dns")
		if r.Status == model.OK {
			r.Status = model.Warn
		}
	} else {
		r.AddNote(model.Info, "env.dns", strings.Join(r.DNSServers, ", "))
	}
	for _, i := range r.Ifaces {
		if i.Default && i.MTU > 0 && i.MTU < 1500 {
			r.AddNote(model.Info, "env.mtu_low", i.Name, i.MTU)
		}
	}
	r.AddNote(model.Info, "env.priv", privSummary(r.Priv))
	r.Elapsed(start)
	return r
}

func fillPing(ps *model.PingStat, sent, recv int, rtts []time.Duration, ttl int) {
	ps.Sent, ps.Recv, ps.TTL = sent, recv, ttl
	if len(rtts) == 0 {
		return
	}
	var sum time.Duration
	mn, mx := rtts[0], rtts[0]
	for _, d := range rtts {
		sum += d
		mn, mx = min(mn, d), max(mx, d)
	}
	ps.MinMs, ps.MaxMs = model.Ms(mn), model.Ms(mx)
	ps.AvgMs = model.Ms(sum / time.Duration(len(rtts)))
}

func privSummary(p model.Privileges) string {
	var parts []string
	if p.Admin {
		parts = append(parts, "admin/root")
	}
	if p.CapNetRaw {
		parts = append(parts, "CAP_NET_RAW")
	}
	if p.UnprivPing {
		parts = append(parts, "ping-socket")
	}
	if p.Npcap {
		parts = append(parts, "Npcap")
	}
	if len(parts) == 0 {
		parts = append(parts, "-")
	}
	icmp, tcp := "✗", "✗"
	if p.ICMPTrace {
		icmp = "✓ " + p.ICMPMethod
	}
	if p.TCPTrace {
		tcp = "✓ " + p.TCPMethod
	}
	return fmt.Sprintf("%s | trace ICMP %s | trace TCP %s", strings.Join(parts, ", "), icmp, tcp)
}

// finishPrivileges complète les raisons d'indisponibilité.
func finishPrivileges(p *model.Privileges) {
	if !p.ICMPTrace && p.ICMPReason.IsZero() {
		p.ICMPReason = msg("priv.icmp_unavailable")
	}
	if !p.TCPTrace && p.TCPReason.IsZero() {
		p.TCPReason = msg("priv.tcp_need_admin")
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func firstV4(addrs []string) netip.Addr {
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
			return ip
		}
	}
	return netip.Addr{}
}

// defaultSource renvoie l'adresse source choisie par l'OS pour joindre
// Internet (aucun paquet n'est émis : connect() UDP seulement).
func defaultSource(network, addr string) string {
	c, err := net.Dial(network, addr)
	if err != nil {
		return ""
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		ip, _ := netip.AddrFromSlice(ua.IP)
		ip = ip.Unmap()
		if ip.IsValid() && !ip.IsUnspecified() {
			return ip.String()
		}
	}
	return ""
}

func interfaces(v4, v6 string) []model.Iface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []model.Iface
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		mi := model.Iface{Name: i.Name, MTU: i.MTU}
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr().Unmap()
			if ip.IsLinkLocalUnicast() && ip.Is6() {
				continue
			}
			mi.Addrs = append(mi.Addrs, pfx.String())
			if s := ip.String(); s == v4 || s == v6 {
				mi.Default = true
			}
		}
		if len(mi.Addrs) > 0 {
			out = append(out, mi)
		}
	}
	slices.SortStableFunc(out, func(a, b model.Iface) int {
		if a.Default != b.Default {
			if a.Default {
				return -1
			}
			return 1
		}
		return 0
	})
	return out
}

// envProxies lit les variables d'environnement de proxy.
func envProxies() []model.ProxyConf {
	var out []model.ProxyConf
	seen := map[string]bool{}
	for _, v := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		for _, name := range []string{v, strings.ToLower(v)} {
			if val := os.Getenv(name); val != "" && !seen[v] {
				seen[v] = true
				out = append(out, model.ProxyConf{Source: "env " + v, Value: val})
			}
		}
	}
	return out
}

// fetchPAC télécharge le fichier PAC (lecture seule) pour vérifier qu'il est
// joignable.
func fetchPAC(ctx context.Context, url string) string {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "-"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err.Error()
	}
	req.Header.Set("User-Agent", UserAgent())
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return shortErr(err)
	}
	resp.Body.Close()
	return resp.Status
}

func shortErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}
