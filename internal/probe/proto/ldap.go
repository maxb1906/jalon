package proto

import (
	"crypto/tls"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/probe"
)

const oidStartTLS = "1.3.6.1.4.1.1466.20037"

var rootDSEAttrs = []string{
	"namingContexts", "defaultNamingContext", "dnsHostName", "supportedLDAPVersion",
	"supportedSASLMechanisms", "vendorName", "vendorVersion", "supportedExtension",
	"domainFunctionality", "serverName",
}

// ldap : StartTLS (opération étendue) ou LDAPS, puis lecture du RootDSE
// anonyme si le serveur l'autorise. Aucun bind n'est effectué.
func (s *session) ldap() error {
	if err := s.open(); err != nil {
		return err
	}
	l := ldap.NewConn(s.conn, s.t.ImplicitTLS)
	l.Start()
	l.SetTimeout(s.cfg.Timeout)
	defer l.Close()
	s.conn = nil // fermé par l.Close

	rootDSE := func() (*ldap.Entry, error) {
		req := ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(s.cfg.Timeout/time.Second)+1, false, "(objectClass=*)", rootDSEAttrs, nil)
		res, err := l.Search(req)
		if err != nil {
			return nil, err
		}
		if len(res.Entries) == 0 {
			return nil, nil
		}
		return res.Entries[0], nil
	}
	entry, err := rootDSE()
	if err != nil {
		s.r.AddNote(model.Info, "ldap.rootdse_denied", shortErr(err))
	}
	if entry != nil {
		for _, a := range entry.Attributes {
			if a.Name == "supportedExtension" {
				if slicesContains(a.Values, oidStartTLS) {
					s.r.TLSOffered = true
				}
				continue
			}
			v := strings.Join(a.Values, ", ")
			if len(v) > 200 {
				v = v[:200] + "…"
			}
			s.r.Info = append(s.r.Info, model.KV{Label: "ldap." + a.Name, Value: v})
		}
		if vn := entry.GetAttributeValue("vendorName"); vn != "" {
			s.r.Banner = sanitize(vn + " " + entry.GetAttributeValue("vendorVersion"))
		} else if dn := entry.GetAttributeValue("dnsHostName"); dn != "" {
			s.r.Banner = sanitize(dn)
		}
	}

	if !s.t.ImplicitTLS {
		var state tls.ConnectionState
		var got bool
		conf := &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			VerifyConnection: func(cs tls.ConnectionState) error {
				state, got = cs, true
				return nil
			},
		}
		if !s.t.IsIP && probeHostIsName(s.host) {
			conf.ServerName = s.host
		}
		t0 := time.Now()
		err := l.StartTLS(conf)
		dur := time.Since(t0)
		switch {
		case err == nil && got:
			s.r.TLSMode = "starttls"
			s.r.TLSOffered = true
			s.tls = probe.AnalyzeState(state, s.host, probe.TLSOptions{Via: "starttls"}, time.Now())
			s.tls.HandshakeMs = model.Ms(dur)
			s.tls.DurationMs = model.Ms(dur)
			s.tls.Via = "starttls"
		case got:
			s.r.TLSMode = "starttls"
			s.tls = probe.AnalyzeState(state, s.host, probe.TLSOptions{Via: "starttls"}, time.Now())
		case s.r.TLSOffered:
			s.r.TLSMode = "refused"
			s.r.AddNote(model.Warn, "ldap.starttls_error", shortErr(err))
		default:
			s.r.TLSMode = "none"
			if err != nil {
				s.r.AddNote(model.Info, "ldap.starttls_error", shortErr(err))
			}
		}
	}
	banner := s.r.Banner
	if banner == "" {
		banner = "-"
	}
	switch {
	case s.t.ImplicitTLS:
		s.r.Set(model.OK, "ldap.ok_tls", banner)
	case s.r.TLSMode == "starttls":
		s.r.Set(model.OK, "ldap.ok_starttls", banner)
	default:
		s.r.Set(model.Warn, "ldap.no_tls", banner)
	}
	return nil
}

func probeHostIsName(h string) bool {
	return strings.ContainsFunc(h, func(r rune) bool { return r >= 'a' && r <= 'z' })
}
