package proto

import (
	"time"

	"github.com/maxb1906/jalon/internal/model"
)

// banner : port non standard. Lecture d'une éventuelle bannière (service
// qui parle en premier), sinon détection de TLS direct.
func (s *session) banner() error {
	if s.t.ImplicitTLS {
		if err := s.open(); err != nil {
			return err
		}
		s.r.Set(model.OK, "banner.tls")
		return nil
	}
	if err := s.dial(); err != nil {
		return err
	}
	_ = s.conn.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	buf := make([]byte, 512)
	n, _ := s.rd.Read(buf)
	s.conn.Close()
	s.conn = nil
	if n > 0 {
		s.r.Banner = sanitize(string(buf[:n]))
		s.r.TLSMode = "none"
		s.r.Set(model.OK, "banner.got", s.r.Banner)
		return nil
	}
	// Silence : le service attend peut-être un ClientHello.
	if err := s.dial(); err != nil {
		return err
	}
	if s.startTLS("direct") {
		s.r.TLSMode = "direct"
		s.r.TLSOffered = true
		s.r.Set(model.OK, "banner.tls")
		return nil
	}
	s.tls = nil
	s.r.TLSMode = "none"
	s.r.Set(model.Info, "banner.silent")
	return nil
}
