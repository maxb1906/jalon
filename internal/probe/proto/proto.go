// Package proto contient les sondes applicatives non-HTTP : SMTP, IMAP,
// POP3, SSH, RDP, LDAP, FTP et bannière générique.
//
// Règle commune : aucune authentification, aucune commande qui modifie un
// état. Chaque sonde s'arrête à la négociation (bannière, capacités,
// STARTTLS, échange de clés).
package proto

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/probe"
)

// Run exécute la sonde du protocole de la cible. Elle renvoie aussi le
// résultat TLS quand une négociation TLS a eu lieu.
func Run(ctx context.Context, cfg probe.Config, t model.Target, ip, host string) (*model.ProtoResult, *model.TLSResult) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 3*cfg.Timeout)
	if cfg.Timeout <= 0 {
		cancel()
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	}
	defer cancel()
	s := &session{ctx: ctx, cfg: cfg, t: t, ip: ip, host: host}
	s.r = &model.ProtoResult{Proto: t.Proto}
	var err error
	switch t.Proto {
	case "smtp":
		err = s.smtp()
	case "imap":
		err = s.imap()
	case "pop3":
		err = s.pop3()
	case "ftp":
		err = s.ftp()
	case "ssh":
		err = s.ssh()
	case "rdp":
		err = s.rdp()
	case "ldap":
		err = s.ldap()
	default:
		err = s.banner()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	if err != nil && s.r.Status == "" {
		s.r.Error = shortErr(err)
		s.r.Set(model.Fail, "proto.error", strings.ToUpper(t.Proto), s.r.Error)
	}
	if s.r.Status == "" {
		s.r.Set(model.OK, "proto.ok", strings.ToUpper(t.Proto))
	}
	if len(s.r.Capabilities) > 0 {
		s.r.AddNote(model.Info, "proto.caps", strings.Join(s.r.Capabilities, ", "))
	}
	for _, kv := range s.r.Info {
		s.r.AddNote(model.Info, "kv."+kv.Label, kv.Value)
	}
	s.r.Elapsed(start)
	return s.r, s.tls
}

// session regroupe l'état d'une sonde.
type session struct {
	ctx  context.Context
	cfg  probe.Config
	t    model.Target
	ip   string
	host string
	conn net.Conn
	rd   *bufio.Reader
	r    *model.ProtoResult
	tls  *model.TLSResult
}

func (s *session) dial() error {
	d := &net.Dialer{Timeout: s.cfg.Timeout}
	c, err := d.DialContext(s.ctx, "tcp", net.JoinHostPort(s.ip, strconv.Itoa(s.t.Port)))
	if err != nil {
		return err
	}
	s.setConn(c)
	return nil
}

func (s *session) setConn(c net.Conn) {
	s.conn = c
	s.rd = bufio.NewReaderSize(c, 8192)
	s.deadline()
}

func (s *session) deadline() {
	if s.conn == nil {
		return
	}
	to := s.cfg.Timeout
	if to <= 0 {
		to = 5 * time.Second
	}
	dl := time.Now().Add(to)
	if cd, ok := s.ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	_ = s.conn.SetDeadline(dl)
}

// startTLS négocie TLS sur la connexion courante et la remplace.
func (s *session) startTLS(via string) bool {
	s.deadline()
	tc, r := probe.TLSHandshake(s.ctx, s.conn, s.host, probe.TLSOptions{Via: via, SelfSignedOK: s.t.Proto == "rdp"})
	s.tls = r
	if tc == nil {
		return false
	}
	s.setConn(tc)
	return true
}

// implicitTLS ouvre la connexion en TLS direct si le port l'exige.
func (s *session) open() error {
	if err := s.dial(); err != nil {
		return err
	}
	if s.t.ImplicitTLS {
		s.r.TLSMode = "direct"
		s.r.TLSOffered = true
		if !s.startTLS("direct") {
			s.r.Set(model.Fail, "proto.tls_failed", strings.ToUpper(s.t.Proto))
			return errTLS
		}
	}
	return nil
}

var errTLS = errors.New("échec TLS")

const maxLine = 4096

func (s *session) readLine() (string, error) {
	s.deadline()
	var b strings.Builder
	for {
		line, isPrefix, err := s.rd.ReadLine()
		if err != nil {
			return b.String(), err
		}
		if b.Len() < maxLine {
			b.Write(line)
		}
		if !isPrefix {
			return b.String(), nil
		}
	}
}

func (s *session) send(cmd string) error {
	s.deadline()
	_, err := fmt.Fprintf(s.conn, "%s\r\n", cmd)
	return err
}

// readReply lit une réponse multi-lignes de type SMTP/FTP (« 250-… » puis
// « 250 … »).
func (s *session) readReply() (int, []string, error) {
	var lines []string
	for i := 0; i < 200; i++ {
		l, err := s.readLine()
		if err != nil {
			return 0, lines, err
		}
		if len(l) < 3 {
			lines = append(lines, l)
			continue
		}
		code, err := strconv.Atoi(l[:3])
		if err != nil {
			lines = append(lines, l)
			continue
		}
		text := ""
		if len(l) > 4 {
			text = l[4:]
		}
		lines = append(lines, text)
		if len(l) == 3 || l[3] == ' ' {
			return code, lines, nil
		}
	}
	return 0, lines, errors.New("réponse trop longue")
}

// sanitize rend une bannière affichable.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
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

func hasCap(caps []string, name string) bool {
	for _, c := range caps {
		f := strings.Fields(strings.ToUpper(c))
		if len(f) > 0 && f[0] == strings.ToUpper(name) {
			return true
		}
		if strings.EqualFold(strings.TrimSpace(c), name) {
			return true
		}
	}
	return false
}

// localEHLO renvoie l'argument d'EHLO : littéral d'adresse locale.
func localEHLO(c net.Conn) string {
	if c == nil {
		return "localhost"
	}
	if ta, ok := c.LocalAddr().(*net.TCPAddr); ok {
		if ta.IP.To4() != nil {
			return "[" + ta.IP.String() + "]"
		}
		return "[IPv6:" + ta.IP.String() + "]"
	}
	return "localhost"
}
