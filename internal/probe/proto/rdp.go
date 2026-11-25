package proto

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/maxb1906/jalon/internal/model"
)

// Protocoles de sécurité RDP (MS-RDPBCGR 2.2.1.1.1).
const (
	rdpProtoRDP      = 0x0
	rdpProtoSSL      = 0x1
	rdpProtoHybrid   = 0x2
	rdpProtoHybridEx = 0x8
)

var rdpFailures = map[uint32]string{
	1: "SSL_REQUIRED_BY_SERVER",
	2: "SSL_NOT_ALLOWED_BY_SERVER",
	3: "SSL_CERT_NOT_ON_SERVER",
	4: "INCONSISTENT_FLAGS",
	5: "HYBRID_REQUIRED_BY_SERVER",
	6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
}

func rdpProtoName(p uint32) string {
	switch p {
	case rdpProtoRDP:
		return "RDP"
	case rdpProtoSSL:
		return "TLS"
	case rdpProtoHybrid:
		return "NLA (CredSSP)"
	case rdpProtoHybridEx:
		return "NLA (CredSSP EX)"
	}
	return "0x" + strconv.FormatUint(uint64(p), 16)
}

// rdpRequest construit un X.224 Connection Request avec RDP_NEG_REQ.
func rdpRequest(requested uint32) []byte {
	cookie := []byte("Cookie: mstshash=jalon\r\n")
	li := 6 + len(cookie) + 8
	total := 4 + 1 + li
	b := make([]byte, 0, total)
	b = append(b, 0x03, 0x00, byte(total>>8), byte(total))
	b = append(b, byte(li), 0xE0, 0, 0, 0, 0, 0)
	b = append(b, cookie...)
	b = append(b, 0x01, 0x00, 0x08, 0x00)
	b = binary.LittleEndian.AppendUint32(b, requested)
	return b
}

// rdpNegResult est la réponse à une négociation.
type rdpNegResult struct {
	selected uint32
	hasNeg   bool   // RDP_NEG_RSP présent
	failure  uint32 // code RDP_NEG_FAILURE (0 = aucun)
}

// parseRDPResponse décode un X.224 Connection Confirm.
func parseRDPResponse(b []byte) (rdpNegResult, error) {
	var r rdpNegResult
	if len(b) < 11 || b[0] != 0x03 {
		return r, errors.New("réponse TPKT invalide")
	}
	if b[5]&0xF0 != 0xD0 {
		return r, errors.New("X.224 Connection Confirm attendu")
	}
	if len(b) >= 19 {
		neg := b[11:19]
		switch neg[0] {
		case 0x02:
			r.hasNeg = true
			r.selected = binary.LittleEndian.Uint32(neg[4:8])
		case 0x03:
			r.failure = binary.LittleEndian.Uint32(neg[4:8])
		}
	}
	return r, nil
}

func (s *session) rdpNegotiate(requested uint32) (rdpNegResult, net.Conn, error) {
	d := &net.Dialer{Timeout: s.cfg.Timeout}
	c, err := d.DialContext(s.ctx, "tcp", net.JoinHostPort(s.ip, strconv.Itoa(s.t.Port)))
	if err != nil {
		return rdpNegResult{}, nil, err
	}
	s.setConn(c)
	if _, err := c.Write(rdpRequest(requested)); err != nil {
		c.Close()
		return rdpNegResult{}, nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(s.rd, hdr[:]); err != nil {
		c.Close()
		return rdpNegResult{}, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	if n < 11 || n > 1024 {
		c.Close()
		return rdpNegResult{}, nil, errors.New("longueur TPKT invalide")
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(s.rd, body); err != nil {
		c.Close()
		return rdpNegResult{}, nil, err
	}
	r, err := parseRDPResponse(append(hdr[:], body...))
	if err != nil {
		c.Close()
	}
	return r, c, err
}

// rdp négocie les protocoles de sécurité acceptés, puis analyse le
// certificat TLS. La négociation s'arrête avant CredSSP : aucun identifiant
// n'est envoyé.
func (s *session) rdp() error {
	info := &model.RDPInfo{}
	s.r.RDP = info
	// 1. Négociation complète (TLS + NLA) : protocole préféré du serveur.
	main, c, err := s.rdpNegotiate(rdpProtoSSL | rdpProtoHybrid | rdpProtoHybridEx)
	if err != nil {
		return err
	}
	switch {
	case main.failure != 0:
		info.Failure = rdpFailures[main.failure]
		c.Close()
	case !main.hasNeg:
		info.Selected = "RDP"
		info.Accepted = append(info.Accepted, "RDP")
		c.Close()
	default:
		info.Selected = rdpProtoName(main.selected)
		if main.selected != rdpProtoRDP {
			s.r.TLSMode = "starttls"
			s.r.TLSOffered = true
			s.startTLS("x224")
		}
		s.conn.Close()
	}
	s.conn = nil

	// 2. Sécurité RDP native (sans TLS) acceptée ?
	if r, c, err := s.rdpNegotiate(rdpProtoRDP); err == nil {
		c.Close()
		if r.failure == 0 && (!r.hasNeg || r.selected == rdpProtoRDP) {
			info.Accepted = appendU(info.Accepted, "RDP")
		}
	}
	// 3. TLS seul (sans NLA) accepté ?
	tlsOnly := false
	if r, c, err := s.rdpNegotiate(rdpProtoSSL); err == nil {
		c.Close()
		if r.failure == 0 && r.hasNeg && r.selected == rdpProtoSSL {
			tlsOnly = true
			info.Accepted = appendU(info.Accepted, "TLS")
		}
		if r.failure == 5 || r.failure == 6 {
			info.NLARequired = true
		}
	}
	s.conn = nil
	if main.hasNeg && (main.selected == rdpProtoHybrid || main.selected == rdpProtoHybridEx) {
		info.Accepted = appendU(info.Accepted, rdpProtoName(main.selected))
	}
	if slicesContains(info.Accepted, "RDP") || tlsOnly {
		info.NLARequired = false
	} else if main.hasNeg && (main.selected == rdpProtoHybrid || main.selected == rdpProtoHybridEx) {
		info.NLARequired = true
	}
	acc := strings.Join(info.Accepted, ", ")
	switch {
	case info.Failure != "":
		s.r.Set(model.Fail, "rdp.failure", info.Failure)
	case info.NLARequired:
		s.r.Set(model.OK, "rdp.ok_nla", info.Selected, acc)
	default:
		s.r.Set(model.Warn, "rdp.no_nla", info.Selected, acc)
	}
	return nil
}

func appendU(l []string, s string) []string {
	if slicesContains(l, s) {
		return l
	}
	return append(l, s)
}

func slicesContains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}
