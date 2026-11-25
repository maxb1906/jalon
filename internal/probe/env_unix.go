//go:build !windows

package probe

import (
	"bufio"
	"net/netip"
	"os"
	"strings"
)

// parseResolvConf extrait les serveurs « nameserver » d'un resolv.conf.
func parseResolvConf(data string) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip, err := netip.ParseAddr(strings.Split(f[1], "%")[0]); err == nil {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func resolvConf(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseResolvConf(string(b))
}

// osDNSServers renvoie les serveurs DNS configurés et, derrière un
// résolveur local (systemd-resolved), les serveurs amont.
func osDNSServers() (servers, upstream []string) {
	servers = resolvConf("/etc/resolv.conf")
	for _, s := range servers {
		if strings.HasPrefix(s, "127.") {
			for _, u := range resolvConf("/run/systemd/resolve/resolv.conf") {
				if !strings.HasPrefix(u, "127.") {
					upstream = append(upstream, u)
				}
			}
			break
		}
	}
	return
}
