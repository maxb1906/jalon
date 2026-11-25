//go:build darwin

package probe

import (
	"bufio"
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/route"

	"github.com/maxb1906/jalon/internal/model"
)

func osGateways() []string {
	rib, err := route.FetchRIB(syscall.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range msgs {
		rm, ok := m.(*route.RouteMessage)
		if !ok || rm.Flags&syscall.RTF_GATEWAY == 0 || len(rm.Addrs) <= syscall.RTAX_GATEWAY {
			continue
		}
		dst, gw := rm.Addrs[syscall.RTAX_DST], rm.Addrs[syscall.RTAX_GATEWAY]
		var ip netip.Addr
		switch d := dst.(type) {
		case *route.Inet4Addr:
			if d.IP != [4]byte{} {
				continue
			}
		case *route.Inet6Addr:
			if d.IP != [16]byte{} {
				continue
			}
		default:
			continue
		}
		switch g := gw.(type) {
		case *route.Inet4Addr:
			ip = netip.AddrFrom4(g.IP)
		case *route.Inet6Addr:
			ip = netip.AddrFrom16(g.IP)
		}
		if ip.IsValid() && !ip.IsUnspecified() {
			s := ip.String()
			found := false
			for _, o := range out {
				found = found || o == s
			}
			if !found {
				out = append(out, s)
			}
		}
	}
	return out
}

// osProxies lit la configuration proxy système via « scutil --proxy »
// (lecture seule).
func osProxies(r *model.EnvResult) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "scutil", "--proxy").Output()
	if err != nil {
		return
	}
	kv := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), " : "); ok {
			kv[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	for _, p := range []string{"HTTP", "HTTPS", "SOCKS"} {
		if kv[p+"Enable"] == "1" {
			r.Proxies = append(r.Proxies, model.ProxyConf{Source: "macos " + p, Value: kv[p+"Proxy"] + ":" + kv[p+"Port"]})
		}
	}
	if kv["ProxyAutoConfigEnable"] == "1" {
		r.PAC = kv["ProxyAutoConfigURLString"]
	}
	if kv["ProxyAutoDiscoveryEnable"] == "1" {
		r.Proxies = append(r.Proxies, model.ProxyConf{Source: "macos WPAD", Value: "auto-discovery"})
	}
}

func osPrivileges(p *model.Privileges) {
	p.Admin = os.Geteuid() == 0
	p.ICMPTrace = true
	if p.Admin {
		p.ICMPMethod = "raw"
		p.TCPTrace, p.TCPMethod = true, "connect+raw-icmp"
	} else {
		p.ICMPMethod = "dgram"
		p.TCPReason = msg("priv.darwin_tcp")
	}
}
