//go:build windows

package probe

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/maxb1906/jalon/internal/model"
)

// adapters renvoie la liste des adaptateurs actifs (GetAdaptersAddresses).
func adapters() []*windows.IpAdapterAddresses {
	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var out []*windows.IpAdapterAddresses
		for a := aa; a != nil; a = a.Next {
			if a.OperStatus == windows.IfOperStatusUp && a.IfType != windows.IF_TYPE_SOFTWARE_LOOPBACK {
				out = append(out, a)
			}
		}
		return out
	}
	return nil
}

func sockaddrIP(sa windows.SocketAddress) netip.Addr {
	if sa.Sockaddr == nil {
		return netip.Addr{}
	}
	switch sa.Sockaddr.Addr.Family {
	case windows.AF_INET:
		p := (*windows.RawSockaddrInet4)(unsafe.Pointer(sa.Sockaddr))
		return netip.AddrFrom4(p.Addr)
	case windows.AF_INET6:
		p := (*windows.RawSockaddrInet6)(unsafe.Pointer(sa.Sockaddr))
		return netip.AddrFrom16(p.Addr)
	}
	return netip.Addr{}
}

func appendUnique(l []string, s string) []string {
	for _, v := range l {
		if v == s {
			return l
		}
	}
	return append(l, s)
}

func osGateways() []string {
	var out []string
	for _, a := range adapters() {
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if ip := sockaddrIP(g.Address); ip.IsValid() && !ip.IsUnspecified() {
				out = appendUnique(out, ip.String())
			}
		}
	}
	return out
}

func osDNSServers() (servers, upstream []string) {
	for _, a := range adapters() {
		if a.FirstGatewayAddress == nil {
			continue // adaptateurs sans passerelle : rarement utilisés pour le DNS
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			ip := sockaddrIP(d.Address)
			if ip.IsValid() && !(ip.Is6() && ip.IsLinkLocalUnicast() && ip.String() == "fec0:0:0:ffff::1") {
				servers = appendUnique(servers, ip.String())
			}
		}
	}
	return servers, nil
}

// osProxies lit la configuration WinINet (utilisateur) et WinHTTP (machine).
func osProxies(r *model.EnvResult) {
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE); err == nil {
		if en, _, err := k.GetIntegerValue("ProxyEnable"); err == nil && en == 1 {
			if s, _, err := k.GetStringValue("ProxyServer"); err == nil && s != "" {
				r.Proxies = append(r.Proxies, model.ProxyConf{Source: "WinINet", Value: s})
			}
		}
		if s, _, err := k.GetStringValue("AutoConfigURL"); err == nil && s != "" {
			r.PAC = s
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.QUERY_VALUE); err == nil {
		if b, _, err := k.GetBinaryValue("DefaultConnectionSettings"); err == nil && len(b) > 8 && b[8]&0x08 != 0 {
			r.Proxies = append(r.Proxies, model.ProxyConf{Source: "WinINet", Value: "auto-detect (WPAD)"})
		}
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections`, registry.QUERY_VALUE); err == nil {
		if b, _, err := k.GetBinaryValue("WinHttpSettings"); err == nil {
			if p := parseWinHTTP(b); p != "" {
				r.Proxies = append(r.Proxies, model.ProxyConf{Source: "WinHTTP", Value: p})
			}
		}
		k.Close()
	}
}

// parseWinHTTP décode la valeur binaire WinHttpSettings.
func parseWinHTTP(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	flags := binary.LittleEndian.Uint32(b[8:12])
	n := int(binary.LittleEndian.Uint32(b[12:16]))
	if flags&2 == 0 || n == 0 || 16+n > len(b) {
		return ""
	}
	return string(b[16 : 16+n])
}

func osPrivileges(p *model.Privileges) {
	p.Admin = windows.GetCurrentProcessToken().IsElevated()
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	if _, err := os.Stat(filepath.Join(sys, "System32", "Npcap", "wpcap.dll")); err == nil {
		p.Npcap = true
	}
	p.ICMPTrace, p.ICMPMethod = true, "IcmpSendEcho"
	if p.Admin {
		p.TCPTrace, p.TCPMethod = true, "connect+raw-icmp"
	} else {
		p.TCPReason = msg("priv.windows_tcp")
	}
}
