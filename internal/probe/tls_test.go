package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/model"
)

type certKey struct {
	cert *x509.Certificate
	key  any
}

var serial int64 = 1

func mkCert(t *testing.T, cn string, parent *certKey, ca bool, notBefore, notAfter time.Time, opts func(*x509.Certificate), rsaBits int) *certKey {
	t.Helper()
	var key any
	var pub any
	if rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			t.Fatal(err)
		}
		key, pub = k, &k.PublicKey
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key, pub = k, &k.PublicKey
	}
	serial++
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{cn + " Org"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  ca,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !ca {
		tpl.DNSNames = []string{cn}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	if opts != nil {
		opts(tpl)
	}
	signer, signKey := tpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, pub, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &certKey{c, key}
}

type pki struct{ root, inter *certKey }

func newPKI(t *testing.T, rootName string) pki {
	now := time.Now()
	root := mkCert(t, rootName, nil, true, now.Add(-time.Hour), now.Add(10*365*24*time.Hour), nil, 0)
	inter := mkCert(t, rootName+" Intermediate", root, true, now.Add(-time.Hour), now.Add(5*365*24*time.Hour), nil, 0)
	return pki{root, inter}
}

func withStores(t *testing.T, system, mozilla []*x509.Certificate) {
	sys := x509.NewCertPool()
	for _, c := range system {
		sys.AddCert(c)
	}
	systemRoots, testMoz = sys, mozilla
	if testMoz == nil {
		testMoz = []*x509.Certificate{}
	}
	t.Cleanup(func() { systemRoots, testMoz = nil, nil })
}

func state(certs ...*x509.Certificate) tls.ConnectionState {
	return tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, PeerCertificates: certs}
}

func TestAnalyzeStateCases(t *testing.T) {
	now := time.Now()
	p := newPKI(t, "Jalon Test Root")
	leaf := func(cn string, nb, na time.Time, o func(*x509.Certificate), bits int) *x509.Certificate {
		return mkCert(t, cn, p.inter, false, nb, na, o, bits).cert
	}
	good := leaf("site.test", now.Add(-time.Hour), now.Add(200*24*time.Hour), nil, 0)

	t.Run("ok", func(t *testing.T) {
		withStores(t, []*x509.Certificate{p.root.cert}, []*x509.Certificate{p.root.cert})
		r := AnalyzeState(state(good, p.inter.cert), "site.test", TLSOptions{}, now)
		if r.Status != model.OK || !r.SystemOK || !r.MozillaOK || !r.HostnameOK || r.Summary.Key != "tls.ok" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("interception", func(t *testing.T) {
		z := newPKI(t, "Zscaler Root CA")
		zl := mkCert(t, "site.test", z.inter, false, now.Add(-time.Hour), now.Add(100*24*time.Hour), nil, 0).cert
		withStores(t, []*x509.Certificate{z.root.cert}, []*x509.Certificate{p.root.cert})
		r := AnalyzeState(state(zl, z.inter.cert), "site.test", TLSOptions{}, now)
		if !r.Intercepted || r.InterceptVendor != "Zscaler" || r.Status != model.Warn || r.Summary.Key != "tls.intercepted" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("interception non installée", func(t *testing.T) {
		f := newPKI(t, "Fortinet CA")
		fl := mkCert(t, "site.test", f.inter, false, now.Add(-time.Hour), now.Add(100*24*time.Hour), nil, 0).cert
		withStores(t, nil, []*x509.Certificate{p.root.cert})
		r := AnalyzeState(state(fl, f.inter.cert), "site.test", TLSOptions{}, now)
		if !r.Intercepted || r.Status != model.Fail || r.InterceptVendor != "Fortinet" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("intermédiaire manquant", func(t *testing.T) {
		withStores(t, []*x509.Certificate{p.root.cert}, []*x509.Certificate{p.root.cert})
		ml := leaf("site.test", now.Add(-time.Hour), now.Add(100*24*time.Hour), func(c *x509.Certificate) {
			c.IssuingCertificateURL = []string{"http://ca.test/inter.crt"}
		}, 0)
		r := AnalyzeState(state(ml), "site.test", TLSOptions{}, now)
		if !r.MissingIntermediate || r.Status != model.Fail {
			t.Errorf("%+v", r)
		}
	})
	t.Run("expiré", func(t *testing.T) {
		withStores(t, []*x509.Certificate{p.root.cert}, []*x509.Certificate{p.root.cert})
		el := leaf("site.test", now.Add(-48*time.Hour), now.Add(-24*time.Hour), nil, 0)
		r := AnalyzeState(state(el, p.inter.cert), "site.test", TLSOptions{}, now)
		if !r.Expired || r.Status != model.Fail || r.Summary.Key != "tls.expired" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("expire bientôt", func(t *testing.T) {
		withStores(t, []*x509.Certificate{p.root.cert}, []*x509.Certificate{p.root.cert})
		sl := leaf("site.test", now.Add(-time.Hour), now.Add(10*24*time.Hour), nil, 0)
		r := AnalyzeState(state(sl, p.inter.cert), "site.test", TLSOptions{}, now)
		if r.Status != model.Warn || r.Summary.Key != "tls.expiring" || r.DaysLeft > 10 {
			t.Errorf("%+v", r)
		}
	})
	t.Run("nom d'hôte", func(t *testing.T) {
		withStores(t, []*x509.Certificate{p.root.cert}, []*x509.Certificate{p.root.cert})
		r := AnalyzeState(state(good, p.inter.cert), "autre.test", TLSOptions{}, now)
		if r.HostnameOK || r.Status != model.Fail || r.Summary.Key != "tls.hostname" {
			t.Errorf("%+v", r)
		}
	})
	t.Run("auto-signé", func(t *testing.T) {
		withStores(t, nil, nil)
		ss := mkCert(t, "self.test", nil, false, now.Add(-time.Hour), now.Add(100*24*time.Hour), nil, 0).cert
		r := AnalyzeState(state(ss), "self.test", TLSOptions{}, now)
		if !r.SelfSigned || r.Status != model.Fail || r.Summary.Key != "tls.selfsigned" {
			t.Errorf("%+v", r)
		}
		r = AnalyzeState(state(ss), "self.test", TLSOptions{SelfSignedOK: true}, now)
		if r.Status != model.Warn || r.Summary.Key != "tls.selfsigned_ok" {
			t.Errorf("RDP : %+v", r)
		}
	})
	t.Run("faible", func(t *testing.T) {
		withStores(t, []*x509.Certificate{p.root.cert}, []*x509.Certificate{p.root.cert})
		wl := leaf("site.test", now.Add(-time.Hour), now.Add(200*24*time.Hour), nil, 1024)
		st := state(wl, p.inter.cert)
		st.Version = tls.VersionTLS10
		r := AnalyzeState(st, "site.test", TLSOptions{}, now)
		if r.Status != model.Warn || len(r.Weak) != 2 || !strings.Contains(strings.Join(r.Weak, ","), "RSA 1024") {
			t.Errorf("%+v", r.Weak)
		}
	})
	t.Run("autorité inconnue", func(t *testing.T) {
		withStores(t, nil, nil)
		r := AnalyzeState(state(good, p.inter.cert), "site.test", TLSOptions{}, now)
		if r.Status != model.Fail || r.Summary.Key != "tls.untrusted" {
			t.Errorf("%+v", r)
		}
	})
}

func TestMatchVendor(t *testing.T) {
	if matchVendor("CN=Kaspersky Anti-Virus Personal Root") != "Kaspersky" || matchVendor("CN=Let's Encrypt") != "" {
		t.Error("matchVendor")
	}
}

func TestTLSDialLocal(t *testing.T) {
	now := time.Now()
	p := newPKI(t, "Jalon Local Root")
	l := mkCert(t, "localhost", p.inter, false, now.Add(-time.Hour), now.Add(100*24*time.Hour), nil, 0)
	withStores(t, []*x509.Certificate{p.root.cert}, []*x509.Certificate{p.root.cert})
	cert := tls.Certificate{Certificate: [][]byte{l.cert.Raw, p.inter.cert.Raw}, PrivateKey: l.key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := DefaultConfig()
	r := TLSDial(context.Background(), cfg, "127.0.0.1", port, "localhost", TLSOptions{ALPN: []string{"h2", "http/1.1"}})
	if r.Status != model.OK || r.ALPN != "h2" || r.Version != "TLS 1.3" || len(r.Chain) != 2 {
		t.Errorf("%+v", r)
	}

	// Serveur qui ne parle pas TLS.
	plain, _ := net.Listen("tcp", "127.0.0.1:0")
	defer plain.Close()
	go func() {
		c, err := plain.Accept()
		if err == nil {
			c.Write([]byte("220 pas du TLS\r\n"))
			c.Close()
		}
	}()
	pp := plain.Addr().(*net.TCPAddr).Port
	r = TLSDial(context.Background(), cfg, "127.0.0.1", pp, "localhost", TLSOptions{})
	if r.Status != model.Fail || r.Error == "" {
		t.Errorf("échec attendu : %+v", r)
	}
	_ = strconv.Itoa
}
