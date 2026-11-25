// Package target analyse les cibles saisies par l'utilisateur.
package target

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/maxb1906/jalon/internal/model"
)

type schemeInfo struct {
	proto       string
	port        int
	implicitTLS bool
}

// Schémas reconnus.
var schemes = map[string]schemeInfo{
	"http":       {"http", 80, false},
	"https":      {"https", 443, true},
	"smtp":       {"smtp", 25, false},
	"submission": {"smtp", 587, false},
	"smtps":      {"smtp", 465, true},
	"imap":       {"imap", 143, false},
	"imaps":      {"imap", 993, true},
	"pop3":       {"pop3", 110, false},
	"pop":        {"pop3", 110, false},
	"pop3s":      {"pop3", 995, true},
	"pops":       {"pop3", 995, true},
	"ssh":        {"ssh", 22, false},
	"sftp":       {"ssh", 22, false},
	"rdp":        {"rdp", 3389, false},
	"ldap":       {"ldap", 389, false},
	"ldaps":      {"ldap", 636, true},
	"ftp":        {"ftp", 21, false},
	"tcp":        {"banner", 0, false},
	"tls":        {"banner", 0, true},
}

// Ports standard → protocole.
var ports = map[int]schemeInfo{
	80:   {"http", 80, false},
	8080: {"http", 8080, false},
	443:  {"https", 443, true},
	8443: {"https", 8443, true},
	25:   {"smtp", 25, false},
	587:  {"smtp", 587, false},
	465:  {"smtp", 465, true},
	143:  {"imap", 143, false},
	993:  {"imap", 993, true},
	110:  {"pop3", 110, false},
	995:  {"pop3", 995, true},
	22:   {"ssh", 22, false},
	3389: {"rdp", 3389, false},
	389:  {"ldap", 389, false},
	636:  {"ldap", 636, true},
	21:   {"ftp", 21, false},
}

// Protos valides pour --proto.
var Protos = []string{"http", "https", "smtp", "imap", "pop3", "ssh", "rdp", "ldap", "ftp", "banner"}

// ImplicitTLSPort indique si un port standard implique TLS direct.
func ImplicitTLSPort(port int) bool {
	switch port {
	case 443, 8443, 465, 993, 995, 636:
		return true
	}
	return false
}

// Parse analyse une cible. proto force le protocole s'il n'est pas vide.
func Parse(raw, proto string) (model.Target, error) {
	raw = strings.TrimSpace(raw)
	t := model.Target{Raw: raw}
	if raw == "" {
		return t, fmt.Errorf("cible vide")
	}
	var host, portStr string
	if i := strings.Index(raw, "://"); i > 0 {
		u, err := url.Parse(raw)
		if err != nil {
			return t, err
		}
		sc := strings.ToLower(u.Scheme)
		info, ok := schemes[sc]
		if !ok {
			return t, fmt.Errorf("schéma inconnu %q", u.Scheme)
		}
		t.Scheme = sc
		t.Proto, t.Port, t.ImplicitTLS = info.proto, info.port, info.implicitTLS
		host, portStr = u.Hostname(), u.Port()
		if t.Proto == "http" || t.Proto == "https" {
			t.Path = u.EscapedPath()
			if u.RawQuery != "" {
				t.Path += "?" + u.RawQuery
			}
		}
	} else {
		// hôte, IP, hôte:port, [v6]:port, v6 nu
		if ap, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
			host = ap.String()
		} else if h, p, err := net.SplitHostPort(raw); err == nil {
			host, portStr = h, p
		} else {
			host = raw
			if i := strings.IndexAny(host, "/?"); i >= 0 {
				t.Path = host[i:]
				host = host[:i]
			}
		}
	}
	if host == "" {
		return t, fmt.Errorf("hôte manquant")
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return t, fmt.Errorf("port invalide %q", portStr)
		}
		t.Port = p
	}
	if t.Scheme == "" {
		if t.Port == 0 {
			t.Scheme, t.Proto, t.Port, t.ImplicitTLS = "https", "https", 443, true
		} else if info, ok := ports[t.Port]; ok {
			t.Proto, t.ImplicitTLS = info.proto, info.implicitTLS
			t.Scheme = schemeFor(info)
		} else {
			t.Scheme, t.Proto = "tcp", "banner"
		}
	}
	if t.Port == 0 {
		return t, fmt.Errorf("port requis pour %s://", t.Scheme)
	}
	if proto != "" {
		proto = strings.ToLower(proto)
		valid := false
		for _, p := range Protos {
			if p == proto {
				valid = true
			}
		}
		if !valid {
			return t, fmt.Errorf("protocole inconnu %q", proto)
		}
		t.Proto = proto
		switch proto {
		case "https":
			t.ImplicitTLS = true
		case "http":
			t.ImplicitTLS = false
		default:
			t.ImplicitTLS = ImplicitTLSPort(t.Port)
		}
	}
	if (t.Proto == "http" || t.Proto == "https") && t.Path == "" {
		t.Path = "/"
	}
	if t.Proto != "http" && t.Proto != "https" {
		t.Path = ""
	}
	if ap, err := netip.ParseAddr(host); err == nil {
		t.IsIP = true
		host = ap.Unmap().String()
	} else if !validHostname(host) {
		return t, fmt.Errorf("nom d'hôte invalide %q", host)
	}
	t.Host = host
	return t, nil
}

func schemeFor(info schemeInfo) string {
	for name, s := range schemes {
		if s == info {
			return name
		}
	}
	return info.proto
}

func validHostname(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c > 127) {
				return false
			}
		}
	}
	return true
}

// URL renvoie l'URL HTTP(S) de la cible.
func URL(t model.Target) string {
	sc := "http"
	if t.Proto == "https" {
		sc = "https"
	}
	h := t.Host
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}
	def := (sc == "http" && t.Port == 80) || (sc == "https" && t.Port == 443)
	if !def {
		h += ":" + strconv.Itoa(t.Port)
	}
	return sc + "://" + h + t.Path
}

// ReadList lit une liste de cibles (une par ligne, # = commentaire).
func ReadList(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}
