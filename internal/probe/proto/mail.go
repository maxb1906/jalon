package proto

import (
	"strings"

	"github.com/maxb1906/jalon/internal/model"
)

// smtp : bannière 220, EHLO, extensions, STARTTLS (25/587) ou TLS direct
// (465). Aucun MAIL FROM, aucune authentification.
func (s *session) smtp() error {
	if err := s.open(); err != nil {
		return err
	}
	code, lines, err := s.readReply()
	if err != nil {
		return err
	}
	if len(lines) > 0 {
		s.r.Banner = sanitize(lines[0])
	}
	if code != 220 {
		s.r.Set(model.Fail, "smtp.bad_banner", code, s.r.Banner)
		return nil
	}
	ehlo := localEHLO(s.conn)
	if err := s.send("EHLO " + ehlo); err != nil {
		return err
	}
	code, lines, err = s.readReply()
	if err != nil {
		return err
	}
	if code != 250 {
		s.r.AddNote(model.Warn, "smtp.ehlo_refused", code)
		_ = s.send("QUIT")
		s.r.Set(model.Warn, "smtp.ehlo_refused", code)
		return nil
	}
	if len(lines) > 1 {
		s.r.Capabilities = lines[1:]
	}
	if !s.t.ImplicitTLS {
		s.r.TLSOffered = hasCap(s.r.Capabilities, "STARTTLS")
		if s.r.TLSOffered {
			if err := s.send("STARTTLS"); err != nil {
				return err
			}
			code, _, err = s.readReply()
			if err != nil {
				return err
			}
			if code == 220 {
				s.r.TLSMode = "starttls"
				if s.startTLS("starttls") {
					if s.send("EHLO "+ehlo) == nil {
						if c, l, err := s.readReply(); err == nil && c == 250 && len(l) > 1 {
							s.r.Info = append(s.r.Info, model.KV{Label: "smtp.caps_after_tls", Value: strings.Join(l[1:], ", ")})
						}
					}
				}
			} else {
				s.r.TLSMode = "refused"
			}
		} else {
			s.r.TLSMode = "none"
		}
	}
	_ = s.send("QUIT")
	for _, c := range s.r.Capabilities {
		if strings.HasPrefix(strings.ToUpper(c), "SIZE ") {
			s.r.Info = append(s.r.Info, model.KV{Label: "smtp.size", Value: strings.TrimSpace(c[5:])})
		}
	}
	s.mailStatus("smtp", "STARTTLS")
	return nil
}

// mailStatus fixe le statut commun SMTP/IMAP/POP3/FTP.
func (s *session) mailStatus(proto, starttls string) {
	banner := s.r.Banner
	if banner == "" {
		banner = "-"
	}
	switch {
	case s.t.ImplicitTLS:
		s.r.Set(model.OK, proto+".ok_tls", banner)
	case s.r.TLSMode == "starttls" && s.tls != nil && s.tls.Error == "":
		s.r.Set(model.OK, proto+".ok_starttls", banner)
	case s.r.TLSMode == "starttls":
		s.r.Set(model.Warn, "proto.starttls_failed", starttls)
	case s.r.TLSMode == "refused":
		s.r.Set(model.Warn, "proto.starttls_refused", starttls)
	default:
		s.r.Set(model.Warn, proto+".no_tls", banner)
	}
}

// imap : bannière, CAPABILITY, STARTTLS ou TLS direct, puis LOGOUT.
func (s *session) imap() error {
	if err := s.open(); err != nil {
		return err
	}
	l, err := s.readLine()
	if err != nil {
		return err
	}
	s.r.Banner = sanitize(l)
	if !strings.HasPrefix(l, "* OK") && !strings.HasPrefix(l, "* PREAUTH") {
		s.r.Set(model.Fail, "imap.bad_banner", s.r.Banner)
		return nil
	}
	caps, err := s.imapCaps("a1")
	if err != nil {
		return err
	}
	s.r.Capabilities = caps
	if !s.t.ImplicitTLS {
		s.r.TLSOffered = hasCap(caps, "STARTTLS")
		s.r.TLSMode = "none"
		if s.r.TLSOffered {
			if err := s.send("a2 STARTTLS"); err != nil {
				return err
			}
			resp, err := s.imapTagged("a2")
			if err != nil {
				return err
			}
			if strings.HasPrefix(resp, "a2 OK") {
				s.r.TLSMode = "starttls"
				if s.startTLS("starttls") {
					if c, err := s.imapCaps("a3"); err == nil {
						s.r.Info = append(s.r.Info, model.KV{Label: "imap.caps_after_tls", Value: strings.Join(c, " ")})
					}
				}
			} else {
				s.r.TLSMode = "refused"
			}
		}
		if hasCap(caps, "LOGINDISABLED") {
			s.r.AddNote(model.OK, "imap.logindisabled")
		}
	}
	_ = s.send("a9 LOGOUT")
	s.mailStatus("imap", "STARTTLS")
	return nil
}

func (s *session) imapTagged(tag string) (string, error) {
	for i := 0; i < 100; i++ {
		l, err := s.readLine()
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(l, tag+" ") {
			return l, nil
		}
	}
	return "", errTLS
}

func (s *session) imapCaps(tag string) ([]string, error) {
	if err := s.send(tag + " CAPABILITY"); err != nil {
		return nil, err
	}
	var caps []string
	for i := 0; i < 100; i++ {
		l, err := s.readLine()
		if err != nil {
			return caps, err
		}
		if c, ok := strings.CutPrefix(l, "* CAPABILITY "); ok {
			caps = strings.Fields(c)
		}
		if strings.HasPrefix(l, tag+" ") {
			return caps, nil
		}
	}
	return caps, nil
}

// pop3 : bannière +OK, CAPA, STLS ou TLS direct, puis QUIT.
func (s *session) pop3() error {
	if err := s.open(); err != nil {
		return err
	}
	l, err := s.readLine()
	if err != nil {
		return err
	}
	s.r.Banner = sanitize(l)
	if !strings.HasPrefix(l, "+OK") {
		s.r.Set(model.Fail, "pop3.bad_banner", s.r.Banner)
		return nil
	}
	caps, _ := s.pop3Capa()
	s.r.Capabilities = caps
	if !s.t.ImplicitTLS {
		s.r.TLSOffered = hasCap(caps, "STLS")
		s.r.TLSMode = "none"
		if s.r.TLSOffered {
			if err := s.send("STLS"); err != nil {
				return err
			}
			l, err := s.readLine()
			if err != nil {
				return err
			}
			if strings.HasPrefix(l, "+OK") {
				s.r.TLSMode = "starttls"
				if s.startTLS("starttls") {
					if c, err := s.pop3Capa(); err == nil && len(c) > 0 {
						s.r.Info = append(s.r.Info, model.KV{Label: "pop3.caps_after_tls", Value: strings.Join(c, ", ")})
					}
				}
			} else {
				s.r.TLSMode = "refused"
			}
		}
	}
	_ = s.send("QUIT")
	s.mailStatus("pop3", "STLS")
	return nil
}

func (s *session) pop3Capa() ([]string, error) {
	if err := s.send("CAPA"); err != nil {
		return nil, err
	}
	l, err := s.readLine()
	if err != nil || !strings.HasPrefix(l, "+OK") {
		return nil, err
	}
	var caps []string
	for i := 0; i < 100; i++ {
		l, err := s.readLine()
		if err != nil {
			return caps, err
		}
		if l == "." {
			break
		}
		caps = append(caps, l)
	}
	return caps, nil
}

// ftp : bannière 220, FEAT, AUTH TLS, puis QUIT.
func (s *session) ftp() error {
	if err := s.open(); err != nil {
		return err
	}
	code, lines, err := s.readReply()
	if err != nil {
		return err
	}
	if len(lines) > 0 {
		s.r.Banner = sanitize(lines[0])
	}
	if code != 220 {
		s.r.Set(model.Fail, "ftp.bad_banner", code, s.r.Banner)
		return nil
	}
	if err := s.send("FEAT"); err != nil {
		return err
	}
	code, lines, err = s.readReply()
	if err == nil && code == 211 && len(lines) > 2 {
		for _, l := range lines[1 : len(lines)-1] {
			s.r.Capabilities = append(s.r.Capabilities, strings.TrimSpace(l))
		}
	}
	s.r.TLSOffered = hasCap(s.r.Capabilities, "AUTH") && strings.Contains(strings.ToUpper(strings.Join(s.r.Capabilities, " ")), "TLS")
	s.r.TLSMode = "none"
	if !s.t.ImplicitTLS {
		// Certains serveurs n'annoncent pas FEAT mais acceptent AUTH TLS.
		if err := s.send("AUTH TLS"); err != nil {
			return err
		}
		code, _, err = s.readReply()
		if err == nil && code == 234 {
			s.r.TLSOffered = true
			s.r.TLSMode = "starttls"
			s.startTLS("starttls")
		} else if s.r.TLSOffered {
			s.r.TLSMode = "refused"
		}
	}
	_ = s.send("QUIT")
	s.mailStatus("ftp", "AUTH TLS")
	return nil
}
