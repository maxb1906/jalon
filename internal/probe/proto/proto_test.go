package proto

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"golang.org/x/crypto/ssh"

	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/probe"
)

func testCert(t *testing.T) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// serve lance un faux serveur qui exécute h pour chaque connexion.
func serve(t *testing.T, h func(c net.Conn)) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				h(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func runProto(t *testing.T, proto string, port int, implicit bool) (*model.ProtoResult, *model.TLSResult) {
	cfg := probe.DefaultConfig()
	cfg.Timeout = 2 * time.Second
	tg := model.Target{Host: "127.0.0.1", Port: port, Proto: proto, ImplicitTLS: implicit, IsIP: true}
	return Run(context.Background(), cfg, tg, "127.0.0.1", "127.0.0.1")
}

type lineSrv struct {
	c  net.Conn
	rd *bufio.Reader
}

func newLine(c net.Conn) *lineSrv { return &lineSrv{c, bufio.NewReader(c)} }
func (l *lineSrv) w(s string)     { io.WriteString(l.c, s+"\r\n") }
func (l *lineSrv) r() string {
	s, _ := l.rd.ReadString('\n')
	return strings.TrimRight(s, "\r\n")
}
func (l *lineSrv) upgrade(cert tls.Certificate) {
	tc := tls.Server(l.c, &tls.Config{Certificates: []tls.Certificate{cert}})
	_ = tc.Handshake()
	l.c, l.rd = tc, bufio.NewReader(tc)
}

func TestSMTPStartTLS(t *testing.T) {
	cert := testCert(t)
	port := serve(t, func(c net.Conn) {
		l := newLine(c)
		l.w("220 mx.test ESMTP")
		for {
			cmd := l.r()
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				l.w("250-mx.test\r\n250-SIZE 35882577\r\n250-STARTTLS\r\n250 8BITMIME")
			case cmd == "STARTTLS":
				l.w("220 go ahead")
				l.upgrade(cert)
			case cmd == "QUIT":
				l.w("221 bye")
				return
			default:
				return
			}
		}
	})
	r, tr := runProto(t, "smtp", port, false)
	if r.Status != model.OK || r.TLSMode != "starttls" || !r.TLSOffered || tr == nil || tr.Error != "" || r.Banner != "mx.test ESMTP" {
		t.Errorf("%+v / %+v", r, tr)
	}
}

func TestSMTPNoTLS(t *testing.T) {
	port := serve(t, func(c net.Conn) {
		l := newLine(c)
		l.w("220-premier\r\n220 mx.test")
		for {
			cmd := l.r()
			if strings.HasPrefix(cmd, "EHLO") {
				l.w("250-mx.test\r\n250 PIPELINING")
			} else {
				l.w("221 bye")
				return
			}
		}
	})
	r, tr := runProto(t, "smtp", port, false)
	if r.Status != model.Warn || r.TLSMode != "none" || tr != nil || r.Summary.Key != "smtp.no_tls" {
		t.Errorf("%+v", r)
	}
}

func TestSMTPImplicitTLS(t *testing.T) {
	cert := testCert(t)
	port := serve(t, func(c net.Conn) {
		l := newLine(c)
		l.upgrade(cert)
		l.w("220 mx.test")
		l.r()
		l.w("250 mx.test")
		l.r()
		l.w("221 bye")
	})
	r, tr := runProto(t, "smtp", port, true)
	if r.Status != model.OK || r.TLSMode != "direct" || tr == nil || r.Summary.Key != "smtp.ok_tls" {
		t.Errorf("%+v", r)
	}
}

func TestIMAP(t *testing.T) {
	cert := testCert(t)
	port := serve(t, func(c net.Conn) {
		l := newLine(c)
		l.w("* OK IMAP ready")
		for {
			cmd := l.r()
			tag, rest, _ := strings.Cut(cmd, " ")
			switch rest {
			case "CAPABILITY":
				l.w("* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED")
				l.w(tag + " OK done")
			case "STARTTLS":
				l.w(tag + " OK begin")
				l.upgrade(cert)
			case "LOGOUT":
				l.w("* BYE")
				l.w(tag + " OK")
				return
			default:
				return
			}
		}
	})
	r, _ := runProto(t, "imap", port, false)
	if r.Status != model.OK || r.TLSMode != "starttls" || len(r.Capabilities) != 3 {
		t.Errorf("%+v", r)
	}
}

func TestPOP3(t *testing.T) {
	port := serve(t, func(c net.Conn) {
		l := newLine(c)
		l.w("+OK POP3 ready")
		for {
			switch l.r() {
			case "CAPA":
				l.w("+OK\r\nUSER\r\nUIDL\r\n.")
			case "QUIT":
				l.w("+OK bye")
				return
			default:
				return
			}
		}
	})
	r, _ := runProto(t, "pop3", port, false)
	if r.Status != model.Warn || r.TLSOffered || len(r.Capabilities) != 2 || r.Summary.Key != "pop3.no_tls" {
		t.Errorf("%+v", r)
	}
}

func TestFTP(t *testing.T) {
	cert := testCert(t)
	port := serve(t, func(c net.Conn) {
		l := newLine(c)
		l.w("220 FTP ready")
		for {
			switch l.r() {
			case "FEAT":
				l.w("211-Features:\r\n AUTH TLS\r\n PBSZ\r\n211 End")
			case "AUTH TLS":
				l.w("234 ok")
				l.upgrade(cert)
			case "QUIT":
				l.w("221 bye")
				return
			default:
				return
			}
		}
	})
	r, tr := runProto(t, "ftp", port, false)
	if r.Status != model.OK || r.TLSMode != "starttls" || tr == nil || r.Summary.Key != "ftp.ok_starttls" {
		t.Errorf("%+v", r)
	}
}

func TestBanner(t *testing.T) {
	port := serve(t, func(c net.Conn) { io.WriteString(c, "REDIS? hello\r\n") })
	r, _ := runProto(t, "banner", port, false)
	if r.Status != model.OK || r.Banner != "REDIS? hello" {
		t.Errorf("%+v", r)
	}
	cert := testCert(t)
	tport := serve(t, func(c net.Conn) {
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
		tc.Handshake()
		time.Sleep(100 * time.Millisecond)
	})
	r, tr := runProto(t, "banner", tport, false)
	if r.Summary.Key != "banner.tls" || tr == nil {
		t.Errorf("TLS silencieux : %+v", r)
	}
}

func TestSSH(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := ssh.NewSignerFromKey(k)
	conf := &ssh.ServerConfig{NoClientAuth: true}
	conf.AddHostKey(signer)
	port := serve(t, func(c net.Conn) { _, _, _, _ = ssh.NewServerConn(c, conf) })
	r, _ := runProto(t, "ssh", port, false)
	if r.SSH == nil || r.SSH.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) || r.SSH.HostKeyType != "ecdsa-sha2-nistp256" {
		t.Fatalf("%+v %+v", r, r.SSH)
	}
	if !strings.HasPrefix(r.Banner, "SSH-2.0-Go") || len(r.SSH.Kex) == 0 {
		t.Errorf("%+v", r.SSH)
	}
	// Serveur aux algorithmes obsolètes.
	old := &ssh.ServerConfig{NoClientAuth: true, Config: ssh.Config{
		KeyExchanges: []string{"curve25519-sha256", "diffie-hellman-group14-sha1"},
		Ciphers:      []string{"aes128-ctr", "aes128-cbc"},
	}}
	old.AddHostKey(signer)
	port = serve(t, func(c net.Conn) { _, _, _, _ = ssh.NewServerConn(c, old) })
	r, _ = runProto(t, "ssh", port, false)
	if r.Status != model.Warn || !strings.Contains(strings.Join(r.SSH.Obsolete, ","), "diffie-hellman-group14-sha1") {
		t.Errorf("obsolète : %+v", r.SSH)
	}
}

func TestParseKexInit(t *testing.T) {
	srv := &kexInit{Kex: []string{"curve25519-sha256"}, HostKey: []string{"ssh-ed25519"}, CiphersCS: []string{"aes128-ctr"}, CiphersSC: []string{"aes128-ctr"},
		MACsCS: []string{"hmac-sha2-256"}, MACsSC: []string{"hmac-sha2-256"}, CompCS: []string{"none"}, CompSC: []string{"none"}}
	p := buildKexInit(srv)
	k, err := parseKexInit(p)
	if err != nil || k.Kex[0] != "curve25519-sha256" || k.HostKey[0] != "ssh-ed25519" || k.CompSC[0] != "none" {
		t.Errorf("%v %+v", err, k)
	}
	if _, err := parseKexInit([]byte{20, 1, 2}); err == nil {
		t.Error("tronqué accepté")
	}
	if pk := sshPacket(p); (len(pk))%8 != 0 || int(binary.BigEndian.Uint32(pk))+4 != len(pk) {
		t.Error("cadrage du paquet")
	}
}

// fakeRDP : NLA exigé ; requested = protocoles demandés.
func fakeRDP(t *testing.T, cert tls.Certificate, nlaOnly bool) int {
	return serve(t, func(c net.Conn) {
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		req := binary.LittleEndian.Uint32(buf[n-4 : n])
		resp := []byte{0x03, 0, 0, 19, 14, 0xD0, 0, 0, 0x12, 0x34, 0}
		switch {
		case req&rdpProtoHybrid != 0:
			resp = append(resp, 0x02, 0, 8, 0)
			resp = binary.LittleEndian.AppendUint32(resp, rdpProtoHybrid)
			c.Write(resp)
			tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
			return
		case nlaOnly:
			resp = append(resp, 0x03, 0, 8, 0)
			resp = binary.LittleEndian.AppendUint32(resp, 5)
		default:
			resp = append(resp, 0x02, 0, 8, 0)
			resp = binary.LittleEndian.AppendUint32(resp, req)
		}
		c.Write(resp)
	})
}

func TestRDP(t *testing.T) {
	cert := testCert(t)
	r, tr := runProto(t, "rdp", fakeRDP(t, cert, true), false)
	if r.RDP == nil || !r.RDP.NLARequired || r.Status != model.OK || tr == nil || tr.Status == model.Fail {
		t.Errorf("NLA : %+v %+v %+v", r, r.RDP, tr)
	}
	r, _ = runProto(t, "rdp", fakeRDP(t, cert, false), false)
	if r.RDP.NLARequired || r.Status != model.Warn {
		t.Errorf("sans NLA : %+v", r.RDP)
	}
	if _, err := parseRDPResponse([]byte{1, 2, 3}); err == nil {
		t.Error("réponse invalide acceptée")
	}
}

func ldapMsg(id int64, op *ber.Packet) []byte {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	p.AppendChild(op)
	return p.Bytes()
}

func ldapResult(tag ber.Tag) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	return op
}

func TestLDAPStartTLS(t *testing.T) {
	cert := testCert(t)
	port := serve(t, func(c net.Conn) {
		var conn net.Conn = c
		for {
			p, err := ber.ReadPacket(conn)
			if err != nil || len(p.Children) < 2 {
				return
			}
			id := p.Children[0].Value.(int64)
			switch p.Children[1].Tag {
			case 3: // SearchRequest → RootDSE
				e := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
				e.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
				attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
				for k, v := range map[string]string{"vendorName": "JalonLDAP", "supportedExtension": oidStartTLS} {
					a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
					a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, k, ""))
					set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
					set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
					a.AppendChild(set)
					attrs.AppendChild(a)
				}
				e.AppendChild(attrs)
				conn.Write(ldapMsg(id, e))
				conn.Write(ldapMsg(id, ldapResult(5)))
			case 23: // ExtendedRequest StartTLS
				conn.Write(ldapMsg(id, ldapResult(24)))
				tc := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
				if tc.Handshake() != nil {
					return
				}
				conn = tc
			default:
				return
			}
		}
	})
	r, tr := runProto(t, "ldap", port, false)
	if r.Status != model.OK || r.TLSMode != "starttls" || !r.TLSOffered || tr == nil || !strings.Contains(r.Banner, "JalonLDAP") {
		t.Errorf("%+v / %+v", r, tr)
	}
}

func TestSanitizeHasCap(t *testing.T) {
	if sanitize("a\tb\x00c\x1b ") != "a bc" {
		t.Error(sanitize("a\tb\x00c\x1b "))
	}
	if !hasCap([]string{"AUTH PLAIN LOGIN", "STARTTLS"}, "starttls") || !hasCap([]string{"AUTH TLS"}, "AUTH") || hasCap([]string{"X"}, "Y") {
		t.Error("hasCap")
	}
}

func TestRefusedConnection(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	r, _ := runProto(t, "smtp", port, false)
	if r.Status != model.Fail || r.Error == "" {
		t.Errorf("%+v", r)
	}
}
