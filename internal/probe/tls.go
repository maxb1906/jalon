package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/x509roots/fallback/bundle"

	"github.com/maxb1906/jalon/internal/model"
)

// systemRoots remplace le magasin système (tests uniquement ; nil = OS).
var systemRoots *x509.CertPool

var (
	mozOnce sync.Once
	mozPool *x509.CertPool
	mozSPKI map[[32]byte]bool
)

// testMoz remplace le bundle Mozilla (tests uniquement).
var testMoz []*x509.Certificate

// mozillaRoots charge le bundle CA Mozilla embarqué.
func mozillaRoots() (*x509.CertPool, map[[32]byte]bool) {
	if testMoz != nil {
		p, m := x509.NewCertPool(), map[[32]byte]bool{}
		for _, c := range testMoz {
			p.AddCert(c)
			m[sha256.Sum256(c.RawSubjectPublicKeyInfo)] = true
		}
		return p, m
	}
	mozOnce.Do(func() {
		mozPool = x509.NewCertPool()
		mozSPKI = map[[32]byte]bool{}
		for r := range bundle.Roots() {
			c, err := x509.ParseCertificate(r.Certificate)
			if err != nil {
				continue
			}
			mozSPKI[sha256.Sum256(c.RawSubjectPublicKeyInfo)] = true
			if r.Constraint != nil {
				mozPool.AddCertWithConstraint(c, r.Constraint)
			} else {
				mozPool.AddCert(c)
			}
		}
	})
	return mozPool, mozSPKI
}

// Éditeurs connus de solutions qui déchiffrent le TLS (proxy d'entreprise,
// antivirus).
var interceptVendors = []struct{ needle, name string }{
	{"zscaler", "Zscaler"}, {"fortinet", "Fortinet"}, {"fortigate", "Fortinet"},
	{"kaspersky", "Kaspersky"}, {"eset", "ESET"}, {"avast", "Avast"}, {"avg ", "AVG"},
	{"bitdefender", "Bitdefender"}, {"sophos", "Sophos"}, {"palo alto", "Palo Alto Networks"},
	{"cisco umbrella", "Cisco Umbrella"}, {"netskope", "Netskope"}, {"blue coat", "Blue Coat / Symantec"},
	{"bluecoat", "Blue Coat / Symantec"}, {"check point", "Check Point"}, {"checkpoint", "Check Point"},
	{"forcepoint", "Forcepoint"}, {"websense", "Forcepoint"}, {"barracuda", "Barracuda"},
	{"mcafee", "McAfee / Skyhigh"}, {"skyhigh", "McAfee / Skyhigh"}, {"trend micro", "Trend Micro"},
	{"norton", "Norton"}, {"symantec web", "Symantec WSS"}, {"sonicwall", "SonicWall"},
	{"watchguard", "WatchGuard"}, {"untangle", "Untangle"}, {"cloudflare gateway", "Cloudflare Gateway"},
	{"cato networks", "Cato Networks"}, {"iboss", "iboss"}, {"mitmproxy", "mitmproxy"},
	{"fiddler", "Fiddler"}, {"charles proxy", "Charles Proxy"}, {"burp", "Burp Suite"},
	{"stormshield", "Stormshield"}, {"f-secure", "F-Secure"}, {"g data", "G DATA"},
}

func matchVendor(s string) string {
	l := strings.ToLower(s)
	for _, v := range interceptVendors {
		if strings.Contains(l, v.needle) {
			return v.name
		}
	}
	return ""
}

// TLSOptions ajuste l'interprétation (ex. RDP : auto-signé courant).
type TLSOptions struct {
	ALPN         []string
	SelfSignedOK bool
	Via          string // direct, starttls
}

// TLSDial ouvre une connexion TCP puis analyse le handshake TLS.
func TLSDial(ctx context.Context, cfg Config, ip string, port int, host string, opt TLSOptions) *model.TLSResult {
	ctx, cancel := cfg.stepCtx(ctx)
	defer cancel()
	c, _, err := dialIP(ctx, ip, port)
	if err != nil {
		r := &model.TLSResult{Error: shortErr(err)}
		r.Set(model.Fail, "tls.tcp_error", r.Error)
		return r
	}
	defer c.Close()
	if opt.Via == "" {
		opt.Via = "direct"
	}
	tc, r := TLSHandshake(ctx, c, host, opt)
	if tc != nil {
		tc.Close()
	}
	return r
}

// TLSHandshake exécute un handshake TLS sur une connexion existante
// (TLS direct ou après STARTTLS) et analyse la chaîne.
func TLSHandshake(ctx context.Context, c net.Conn, host string, opt TLSOptions) (*tls.Conn, *model.TLSResult) {
	sni := host
	if net.ParseIP(host) != nil {
		sni = ""
	}
	conf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // vérification faite à la main, double magasin
		NextProtos:         opt.ALPN,
		MinVersion:         tls.VersionTLS10,
	}
	tc := tls.Client(c, conf)
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	start := time.Now()
	err := tc.HandshakeContext(ctx)
	dur := time.Since(start)
	_ = c.SetDeadline(time.Time{})
	if err != nil {
		r := &model.TLSResult{SNI: sni, Via: opt.Via, Error: shortErr(err), HandshakeMs: model.Ms(dur)}
		kind := handshakeErrKind(err)
		r.Set(model.Fail, "tls.handshake_"+kind, r.Error)
		if kind == "reset" || kind == "eof" {
			r.AddNote(model.Warn, "tls.sni_filter_hint")
		}
		r.DurationMs = model.Ms(dur)
		return nil, r
	}
	r := AnalyzeState(tc.ConnectionState(), host, opt, time.Now())
	r.HandshakeMs = model.Ms(dur)
	r.DurationMs = model.Ms(dur)
	r.Via = opt.Via
	return tc, r
}

func handshakeErrKind(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "reset by peer") || strings.Contains(err.Error(), "forcibly closed"):
		return "reset"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	var ae tls.AlertError
	if errors.As(err, &ae) || strings.Contains(err.Error(), "alert") {
		return "alert"
	}
	return "error"
}

func certInfo(c *x509.Certificate) model.CertInfo {
	fp := sha256.Sum256(c.Raw)
	ci := model.CertInfo{
		Subject:   nameOf(c.Subject.CommonName, c.Subject.Organization, c.Subject.String()),
		Issuer:    nameOf(c.Issuer.CommonName, c.Issuer.Organization, c.Issuer.String()),
		NotBefore: c.NotBefore.UTC(),
		NotAfter:  c.NotAfter.UTC(),
		DNSNames:  c.DNSNames,
		SigAlg:    c.SignatureAlgorithm.String(),
		SHA256:    hex.EncodeToString(fp[:]),
		IsCA:      c.IsCA,
	}
	for _, ip := range c.IPAddresses {
		ci.IPs = append(ci.IPs, ip.String())
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		ci.KeyType, ci.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		ci.KeyType, ci.KeyBits = "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		ci.KeyType, ci.KeyBits = "Ed25519", 256
	default:
		ci.KeyType = fmt.Sprintf("%T", k)
	}
	ci.SelfSigned = isSelfSigned(c)
	return ci
}

func nameOf(cn string, org []string, full string) string {
	switch {
	case cn != "" && len(org) > 0:
		return cn + " (" + org[0] + ")"
	case cn != "":
		return cn
	case len(org) > 0:
		return org[0]
	}
	return full
}

// isSelfSigned : émetteur = sujet et signature vérifiable avec sa propre clé
// (CheckSignatureFrom exigerait en plus le drapeau CA).
func isSelfSigned(c *x509.Certificate) bool {
	return string(c.RawIssuer) == string(c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// AnalyzeState valide la chaîne présentée contre le magasin système et le
// bundle Mozilla, et détecte interception, expiration, nom d'hôte,
// intermédiaire manquant et algorithmes faibles.
func AnalyzeState(st tls.ConnectionState, host string, opt TLSOptions, now time.Time) *model.TLSResult {
	r := &model.TLSResult{
		Version:     tls.VersionName(st.Version),
		Cipher:      tls.CipherSuiteName(st.CipherSuite),
		ALPN:        st.NegotiatedProtocol,
		SNI:         st.ServerName,
		OCSPStapled: len(st.OCSPResponse) > 0,
	}
	if net.ParseIP(host) == nil {
		r.SNI = host
	}
	certs := st.PeerCertificates
	if len(certs) == 0 {
		r.Set(model.Fail, "tls.no_cert")
		return r
	}
	for _, c := range certs {
		r.Chain = append(r.Chain, certInfo(c))
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	moz, mozSPKISet := mozillaRoots()
	sysChains, sysErr := leaf.Verify(x509.VerifyOptions{Intermediates: inter, Roots: systemRoots, CurrentTime: now})
	_, mozErr := leaf.Verify(x509.VerifyOptions{Intermediates: inter, Roots: moz, CurrentTime: now})
	r.SystemOK, r.MozillaOK = sysErr == nil, mozErr == nil
	if sysErr != nil {
		r.SystemErr = shortErr(sysErr)
	}
	if mozErr != nil {
		r.MozillaErr = shortErr(mozErr)
	}
	r.HostnameOK = leaf.VerifyHostname(host) == nil
	r.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
	r.Expired = now.After(leaf.NotAfter)
	notYet := now.Before(leaf.NotBefore)
	r.SelfSigned = isSelfSigned(leaf)

	// Interception / intermédiaire manquant.
	if r.SystemOK && !r.MozillaOK && len(sysChains) > 0 {
		root := sysChains[0][len(sysChains[0])-1]
		if mozSPKISet[sha256.Sum256(root.RawSubjectPublicKeyInfo)] {
			r.MissingIntermediate = true
		} else {
			r.Intercepted = true
			r.InterceptIssuer = nameOf(root.Subject.CommonName, root.Subject.Organization, root.Subject.String())
		}
	}
	if !r.SystemOK && !r.MozillaOK && !r.SelfSigned && !r.Expired {
		for _, c := range certs {
			if v := matchVendor(c.Issuer.String()); v != "" {
				r.Intercepted = true
				r.InterceptIssuer = nameOf(c.Issuer.CommonName, c.Issuer.Organization, c.Issuer.String())
			}
		}
		last := certs[len(certs)-1]
		if !r.Intercepted && !isSelfSigned(last) && len(leaf.IssuingCertificateURL) > 0 && isUnknownAuthority(mozErr) {
			r.MissingIntermediate = true
		}
	}
	if r.Intercepted {
		r.InterceptVendor = matchVendor(r.InterceptIssuer)
		if r.InterceptVendor == "" {
			for _, c := range certs {
				if v := matchVendor(c.Issuer.String()); v != "" {
					r.InterceptVendor = v
				}
			}
		}
	}

	// Algorithmes faibles.
	if st.Version < tls.VersionTLS12 {
		r.Weak = append(r.Weak, r.Version)
	}
	for _, cs := range tls.InsecureCipherSuites() {
		if cs.ID == st.CipherSuite {
			r.Weak = append(r.Weak, r.Cipher)
		}
	}
	for i, c := range certs {
		if i > 0 && isSelfSigned(c) {
			continue // la signature d'une racine n'a pas d'importance
		}
		switch c.SignatureAlgorithm {
		case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
			r.Weak = appendU(r.Weak, c.SignatureAlgorithm.String())
		}
		if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
			r.Weak = appendU(r.Weak, fmt.Sprintf("RSA %d", k.N.BitLen()))
		}
	}

	// Statut et résumé.
	cn := r.Chain[0].Subject
	switch {
	case r.Expired:
		r.Set(model.Fail, "tls.expired", cn, leaf.NotAfter.Format("2006-01-02"))
	case notYet:
		r.Set(model.Fail, "tls.not_yet", cn, leaf.NotBefore.Format("2006-01-02"))
	case !r.HostnameOK && !(opt.SelfSignedOK && r.SelfSigned):
		r.Set(model.Fail, "tls.hostname", host, strings.Join(append(append([]string{}, leaf.DNSNames...), r.Chain[0].IPs...), ", "))
	case r.SelfSigned && opt.SelfSignedOK:
		r.Set(model.Warn, "tls.selfsigned_ok", r.Version, cn)
	case r.SelfSigned:
		r.Set(model.Fail, "tls.selfsigned", cn)
	case r.Intercepted && r.SystemOK:
		r.Set(model.Warn, "tls.intercepted", r.InterceptIssuer, firstNonEmpty(r.InterceptVendor, "?"))
	case r.Intercepted:
		r.Set(model.Fail, "tls.intercepted_untrusted", r.InterceptIssuer, firstNonEmpty(r.InterceptVendor, "?"))
	case r.MissingIntermediate && r.SystemOK:
		r.Set(model.Warn, "tls.missing_intermediate_sys", r.Chain[0].Issuer)
	case r.MissingIntermediate:
		r.Set(model.Fail, "tls.missing_intermediate", r.Chain[0].Issuer)
	case !r.SystemOK && !r.MozillaOK:
		r.Set(model.Fail, "tls.untrusted", r.Chain[0].Issuer, firstNonEmpty(r.MozillaErr, r.SystemErr))
	case r.DaysLeft < 30:
		r.Set(model.Warn, "tls.expiring", r.Version, cn, r.DaysLeft)
	case len(r.Weak) > 0:
		r.Set(model.Warn, "tls.weak", r.Version, strings.Join(r.Weak, ", "))
	default:
		r.Set(model.OK, "tls.ok", r.Version, cn, leaf.NotAfter.Format("2006-01-02"), r.DaysLeft)
	}
	if r.Status != model.Fail || r.Expired || !r.HostnameOK {
		// Constats secondaires toujours utiles.
		if r.DaysLeft < 30 && !r.Expired && r.Summary.Key != "tls.expiring" {
			r.AddNote(model.Warn, "tls.note_expiring", r.DaysLeft)
		}
		if len(r.Weak) > 0 && r.Summary.Key != "tls.weak" {
			r.AddNote(model.Warn, "tls.note_weak", strings.Join(r.Weak, ", "))
		}
	}
	r.AddNote(model.Info, "tls.details", r.Version, r.Cipher, firstNonEmpty(r.ALPN, "-"), firstNonEmpty(r.SNI, "-"))
	r.AddNote(model.Info, "tls.chain", len(r.Chain), r.Chain[0].Issuer, r.Chain[0].KeyType, r.Chain[0].KeyBits)
	if r.SystemOK != r.MozillaOK {
		r.AddNote(model.Info, "tls.stores", okKO(r.SystemOK), okKO(r.MozillaOK))
	}
	if r.OCSPStapled {
		r.AddNote(model.Info, "tls.ocsp_yes")
	} else {
		r.AddNote(model.Info, "tls.ocsp_no")
	}
	return r
}

func okKO(b bool) string {
	if b {
		return "OK"
	}
	return "KO"
}

func isUnknownAuthority(err error) bool {
	var ua x509.UnknownAuthorityError
	return errors.As(err, &ua)
}
