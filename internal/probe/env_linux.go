//go:build linux

package probe

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/maxb1906/jalon/internal/model"
)

func osGateways() []string {
	var out []string
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		out = append(out, parseProcRoute(string(b))...)
	}
	if b, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
		out = append(out, parseProcIPv6Route(string(b))...)
	}
	return out
}

// parseProcRoute lit /proc/net/route : route par défaut = destination 0.
func parseProcRoute(data string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		g, err := hex.DecodeString(f[2])
		if err != nil || len(g) != 4 {
			continue
		}
		var a [4]byte
		binary.LittleEndian.PutUint32(a[:], binary.BigEndian.Uint32(g))
		ip := netip.AddrFrom4(a)
		if !ip.IsUnspecified() && !contains(out, ip.String()) {
			out = append(out, ip.String())
		}
	}
	return out
}

// parseProcIPv6Route lit /proc/net/ipv6_route : destination ::/0 avec
// prochain saut non nul.
func parseProcIPv6Route(data string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 10 || f[0] != strings.Repeat("0", 32) || f[1] != "00" {
			continue
		}
		g, err := hex.DecodeString(f[4])
		if err != nil || len(g) != 16 {
			continue
		}
		ip := netip.AddrFrom16([16]byte(g))
		if ip.IsUnspecified() {
			continue
		}
		s := ip.String()
		if ip.IsLinkLocalUnicast() {
			s += "%" + f[9]
		}
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func osProxies(r *model.EnvResult) {}

func osPrivileges(p *model.Privileges) {
	p.Admin = os.Geteuid() == 0
	if b, err := os.ReadFile("/proc/self/status"); err == nil {
		p.CapNetRaw = capNetRaw(string(b))
	}
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ping_group_range"); err == nil {
		gids, _ := os.Getgroups()
		gids = append(gids, os.Getgid())
		p.UnprivPing = pingAllowed(string(b), gids)
	}
	switch {
	case p.Admin || p.CapNetRaw:
		p.ICMPTrace, p.ICMPMethod = true, "raw"
		p.TCPTrace, p.TCPMethod = true, "connect+raw-icmp"
		p.RawSniffTTL = true
	case p.UnprivPing:
		p.ICMPTrace, p.ICMPMethod = true, "ping-socket"
	default:
		p.ICMPReason = msg("priv.linux_no_icmp")
	}
	if !p.TCPTrace {
		p.TCPReason = msg("priv.linux_tcp")
	}
}

// capNetRaw lit le bit CAP_NET_RAW (13) de CapEff dans /proc/self/status.
func capNetRaw(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && n&(1<<13) != 0
		}
	}
	return false
}

// pingAllowed vérifie si un des groupes est dans ping_group_range.
func pingAllowed(rng string, gids []int) bool {
	f := strings.Fields(rng)
	if len(f) != 2 {
		return false
	}
	lo, err1 := strconv.Atoi(f[0])
	hi, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return false
	}
	for _, g := range gids {
		if g >= lo && g <= hi {
			return true
		}
	}
	return false
}
