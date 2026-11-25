package probe

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/maxb1906/jalon/internal/model"
)

// Libellés des résolveurs.
const (
	resSystem = "system"
	resOS     = "os"
)

// dnsQuery interroge un serveur précis en UDP, avec repli TCP si la réponse
// est tronquée ou si l'UDP échoue.
func dnsQuery(ctx context.Context, server, name string, qtype uint16, class uint16) (*dns.Msg, time.Duration, string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Question[0].Qclass = class
	m.RecursionDesired = true
	m.AuthenticatedData = true
	m.SetEdns0(1232, false)
	addr := dnsAddr(server)
	dl, ok := ctx.Deadline()
	timeout := 3 * time.Second
	if ok {
		timeout = min(time.Until(dl), timeout)
	}
	c := &dns.Client{Net: "udp", Timeout: timeout}
	r, rtt, err := c.ExchangeContext(ctx, m, addr)
	if err == nil && !r.Truncated {
		return r, rtt, "udp", nil
	}
	ct := &dns.Client{Net: "tcp", Timeout: timeout}
	r2, rtt2, err2 := ct.ExchangeContext(ctx, m, addr)
	if err2 == nil {
		return r2, rtt2, "tcp", nil
	}
	if err == nil {
		return r, rtt, "udp", nil // tronquée mais exploitable
	}
	return nil, 0, "udp", err
}

// dnsAddr ajoute le port 53 sauf si le serveur précise déjà un port.
func dnsAddr(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

// dohQuery interroge un résolveur DNS-over-HTTPS (RFC 8484).
func dohQuery(ctx context.Context, url, name string, qtype, class uint16) (*dns.Msg, time.Duration, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.Question[0].Qclass = class
	m.RecursionDesired = true
	m.AuthenticatedData = true
	m.Id = 0
	b, err := m.Pack()
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", UserAgent())
	start := time.Now()
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	rtt := time.Since(start)
	if err != nil {
		return nil, rtt, err
	}
	if resp.StatusCode != 200 {
		return nil, rtt, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, rtt, err
	}
	return r, rtt, nil
}

var dohClient = &http.Client{
	Timeout:   5 * time.Second,
	Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 4 * time.Second},
}

// DoH utilisés pour la détection d'interception (adresses IP : aucune
// dépendance au DNS local).
var dohServers = map[string]string{
	"1.1.1.1": "https://1.1.1.1/dns-query",
	"8.8.8.8": "https://8.8.8.8/dns-query",
}

// fillAnswer remplit une DNSAnswer à partir des réponses A et AAAA.
func fillAnswer(a *model.DNSAnswer, ra, raaaa *dns.Msg) {
	var ttl uint32
	setTTL := func(t uint32) {
		if ttl == 0 || t < ttl {
			ttl = t
		}
	}
	for _, m := range []*dns.Msg{ra, raaaa} {
		if m == nil {
			continue
		}
		for _, rr := range m.Answer {
			switch v := rr.(type) {
			case *dns.A:
				a.A = appendU(a.A, v.A.String())
				setTTL(v.Hdr.Ttl)
			case *dns.AAAA:
				a.AAAA = appendU(a.AAAA, v.AAAA.String())
				setTTL(v.Hdr.Ttl)
			case *dns.CNAME:
				a.CNAME = appendU(a.CNAME, strings.TrimSuffix(v.Target, "."))
			}
		}
	}
	a.TTL = ttl
	if ra != nil {
		a.Rcode = dns.RcodeToString[ra.Rcode]
		a.AD = ra.AuthenticatedData
		if ra.Rcode == dns.RcodeSuccess && raaaa != nil && raaaa.Rcode != dns.RcodeSuccess && len(a.A) == 0 {
			a.Rcode = dns.RcodeToString[raaaa.Rcode]
		}
	} else if raaaa != nil {
		a.Rcode = dns.RcodeToString[raaaa.Rcode]
	}
}

// shortList joint au plus n éléments, puis « (+k) ».
func shortList(l []string, n int) string {
	if len(l) <= n {
		return strings.Join(l, ", ")
	}
	return strings.Join(l[:n], ", ") + fmt.Sprintf(" (+%d)", len(l)-n)
}

func appendU(l []string, s string) []string {
	if slices.Contains(l, s) {
		return l
	}
	return append(l, s)
}

// resolveAt interroge un serveur pour A + AAAA.
func resolveAt(ctx context.Context, label, server, name string) model.DNSAnswer {
	a := model.DNSAnswer{Resolver: label, Server: server}
	var ra, raaaa *dns.Msg
	var rtt time.Duration
	var errA, errAAAA error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ra, rtt, a.Transport, errA = dnsQuery(ctx, server, name, dns.TypeA, dns.ClassINET)
	}()
	go func() {
		defer wg.Done()
		raaaa, _, _, errAAAA = dnsQuery(ctx, server, name, dns.TypeAAAA, dns.ClassINET)
	}()
	wg.Wait()
	a.RTTMs = model.Ms(rtt)
	if errA != nil && errAAAA != nil {
		a.Error = dnsErr(errA)
		return a
	}
	fillAnswer(&a, ra, raaaa)
	return a
}

func dnsErr(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return shortErr(err)
}

// resolveOS utilise le résolveur de l'OS (fichier hosts, VPN, NRPT…).
func resolveOS(ctx context.Context, name string) model.DNSAnswer {
	a := model.DNSAnswer{Resolver: resOS, Transport: "os"}
	start := time.Now()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", name)
	a.RTTMs = model.Ms(time.Since(start))
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			a.Rcode = "NXDOMAIN"
			return a
		}
		a.Error = dnsErr(err)
		return a
	}
	a.Rcode = "NOERROR"
	for _, ip := range ips {
		ip = ip.Unmap()
		if ip.Is4() {
			a.A = appendU(a.A, ip.String())
		} else {
			a.AAAA = appendU(a.AAAA, ip.String())
		}
	}
	return a
}

// DNS compare la résolution de la cible entre le résolveur système et les
// résolveurs publics.
func DNS(ctx context.Context, cfg Config, t model.Target) *model.DNSResult {
	start := time.Now()
	r := &model.DNSResult{Name: t.Host}
	ctx, cancel := cfg.stepCtx(ctx)
	defer cancel()

	name := t.Host
	r.Answers = resolveAll(ctx, cfg, name)

	// SMTP : enregistrements MX ; si le nom n'a pas d'adresse, on contacte
	// le premier MX.
	if t.Proto == "smtp" {
		r.MX = lookupMX(ctx, cfg, name)
		// Port 25 vers un domaine de messagerie : c'est le MX qui reçoit le
		// courrier. Idem si le nom n'a pas d'adresse.
		if len(r.MX) > 0 && (!anyIPs(r.Answers) || (t.Port == 25 && !isMXHost(r.MX, name))) {
			mx := strings.Fields(r.MX[0])
			host := mx[len(mx)-1]
			r.ConnectHost = host
			r.AddNote(model.Info, "dns.use_mx", host)
			r.Answers = resolveAll(ctx, cfg, host)
		}
	}
	if srv := srvNames(t); len(srv) > 0 {
		r.SRV = lookupSRV(ctx, cfg, srv, name)
	}

	r.Verdict = classifyDNS(r.Answers)
	r.IPv4, r.IPv6, r.Fallback = chooseIPs(r.Answers)
	local := localAnswer(r.Answers)
	ipList := shortList(append(append([]string{}, r.IPv4...), r.IPv6...), 4)
	shown := name
	if r.ConnectHost != "" {
		shown = r.ConnectHost
	}
	switch r.Verdict {
	case "same":
		r.Set(model.OK, "dns.same", shown, ipList)
	case "cdn":
		r.Set(model.OK, "dns.cdn", shown, ipList)
	case "internal":
		r.Set(model.OK, "dns.internal", shown, ipList)
	case "public_fail":
		r.Set(model.Warn, "dns.public_fail", shown, ipList)
	case "differs":
		r.Set(model.Warn, "dns.differs", shown, shortList(local.IPs(), 4), shortList(publicIPs(r.Answers), 4))
	case "sinkhole":
		r.Set(model.Fail, "dns.sinkhole", shown, shortList(local.IPs(), 4))
	case "local_nx":
		r.Set(model.Fail, "dns.local_nx", shown, ipList)
	case "local_fail":
		r.Set(model.Fail, "dns.local_fail", shown, firstNonEmpty(local.Error, local.Rcode), ipList)
	case "nx":
		r.Set(model.Fail, "dns.nx", shown)
	case "noaddr":
		r.Set(model.Fail, "dns.noaddr", shown)
	default:
		r.Set(model.Fail, "dns.all_fail", shown)
	}
	if r.Fallback {
		r.AddNote(model.Warn, "dns.fallback", ipList)
	}
	// Résolveur OS ≠ requête directe : fichier hosts, VPN, cache…
	var sys, osa *model.DNSAnswer
	for i := range r.Answers {
		switch r.Answers[i].Resolver {
		case resSystem:
			sys = &r.Answers[i]
		case resOS:
			osa = &r.Answers[i]
		}
	}
	if sys != nil && osa != nil && len(osa.IPs()) > 0 && len(sys.IPs()) > 0 && !intersects(sys.IPs(), osa.IPs()) {
		r.AddNote(model.Warn, "dns.os_differs", strings.Join(osa.IPs(), ", "), strings.Join(sys.IPs(), ", "))
	}
	if isPrivateList(local.IPs()) && r.Verdict == "differs" {
		r.AddNote(model.Info, "dns.private_ip")
	}
	for _, a := range r.Answers {
		if a.AD {
			r.AddNote(model.Info, "dns.ad", a.Resolver)
			break
		}
	}
	if len(r.IPv4) > 0 && len(r.IPv6) == 0 {
		r.AddNote(model.Info, "dns.no_aaaa")
	}
	if len(r.MX) > 0 {
		r.AddNote(model.Info, "dns.mx", strings.Join(r.MX, ", "))
	}
	if len(r.SRV) > 0 {
		r.AddNote(model.Info, "dns.srv", strings.Join(r.SRV, ", "))
	}
	r.Elapsed(start)
	return r
}

func resolveAll(ctx context.Context, cfg Config, name string) []model.DNSAnswer {
	type job struct{ label, server string }
	var jobs []job
	if cfg.Env != nil && len(cfg.Env.DNSServers) > 0 {
		jobs = append(jobs, job{resSystem, cfg.Env.DNSServers[0]})
	}
	for _, p := range cfg.PublicResolvers {
		jobs = append(jobs, job{p, p})
	}
	out := make([]model.DNSAnswer, len(jobs)+1)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = resolveAt(ctx, j.label, j.server, name)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		out[len(jobs)] = resolveOS(ctx, name)
	}()
	wg.Wait()
	return out
}

func anyIPs(ans []model.DNSAnswer) bool {
	for _, a := range ans {
		if len(a.IPs()) > 0 {
			return true
		}
	}
	return false
}

func isPublicLabel(l string) bool { return l != resSystem && l != resOS }

// localAnswer renvoie la réponse du résolveur local : requête directe au
// serveur configuré, sinon résolveur de l'OS.
func localAnswer(ans []model.DNSAnswer) model.DNSAnswer {
	for _, a := range ans {
		if a.Resolver == resSystem {
			return a
		}
	}
	for _, a := range ans {
		if a.Resolver == resOS {
			return a
		}
	}
	return model.DNSAnswer{Error: "none"}
}

func publicIPs(ans []model.DNSAnswer) []string {
	var out []string
	for _, a := range ans {
		if isPublicLabel(a.Resolver) {
			for _, ip := range a.IPs() {
				out = appendU(out, ip)
			}
		}
	}
	return out
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// netOf renvoie le préfixe /24 (IPv4) ou /48 (IPv6) d'une adresse.
func netOf(s string) string {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	bits := 24
	if ip.Is6() {
		bits = 48
	}
	p, _ := ip.Prefix(bits)
	return p.String()
}

// intersectsNet : au moins une adresse dans le même réseau.
func intersectsNet(a, b []string) bool {
	if intersects(a, b) {
		return true
	}
	for _, x := range a {
		for _, y := range b {
			if netOf(x) == netOf(y) {
				return true
			}
		}
	}
	return false
}

func isPrivateList(ips []string) bool {
	for _, s := range ips {
		if ip, err := netip.ParseAddr(s); err == nil && (ip.IsPrivate() || ip.IsLoopback()) {
			return true
		}
	}
	return false
}

func isSinkhole(ips []string) bool {
	if len(ips) == 0 {
		return false
	}
	for _, s := range ips {
		ip, err := netip.ParseAddr(s)
		if err != nil || !(ip.IsUnspecified() || ip.IsLoopback()) {
			return false
		}
	}
	return true
}

// classifyDNS compare la réponse locale aux réponses publiques.
func classifyDNS(ans []model.DNSAnswer) string {
	local := localAnswer(ans)
	var pubs []model.DNSAnswer
	for _, a := range ans {
		if isPublicLabel(a.Resolver) {
			pubs = append(pubs, a)
		}
	}
	localIPs := local.IPs()
	// L'OS peut répondre même si la requête directe échoue (VPN, hosts).
	if len(localIPs) == 0 {
		for _, a := range ans {
			if a.Resolver == resOS && len(a.IPs()) > 0 {
				localIPs = a.IPs()
				local = a
			}
		}
	}
	var pubOK [][]string
	pubNX, pubErr := 0, 0
	for _, p := range pubs {
		switch {
		case len(p.IPs()) > 0:
			pubOK = append(pubOK, p.IPs())
		case p.Rcode == "NXDOMAIN":
			pubNX++
		case p.Rcode == "NOERROR" && p.Error == "":
			// le nom existe sans adresse
		default:
			pubErr++
		}
	}
	localNX := local.Rcode == "NXDOMAIN"
	localFailed := local.Error != "" || (local.Rcode != "" && local.Rcode != "NOERROR" && !localNX)

	switch {
	case len(localIPs) > 0 && isSinkhole(localIPs) && len(pubOK) > 0 && !isSinkhole(pubOK[0]):
		return "sinkhole"
	case len(localIPs) > 0 && len(pubOK) == 0 && pubNX > 0:
		return "internal"
	case len(localIPs) > 0 && len(pubOK) == 0:
		return "public_fail"
	case len(localIPs) > 0:
		for _, p := range pubOK {
			if intersects(localIPs, p) {
				return "same"
			}
		}
		for _, p := range pubOK {
			if intersectsNet(localIPs, p) {
				return "cdn" // même réseau, adresse tournante
			}
		}
		// Les publics sont-ils d'accord entre eux ?
		agree := len(pubOK) < 2
		for i := 1; i < len(pubOK); i++ {
			if intersectsNet(pubOK[0], pubOK[i]) {
				agree = true
			}
		}
		if agree {
			return "differs"
		}
		return "cdn"
	case len(pubOK) > 0 && localNX:
		return "local_nx"
	case len(pubOK) > 0 && (localFailed || local.Rcode == "NOERROR"):
		if local.Rcode == "NOERROR" && local.Error == "" {
			return "local_nx" // NOERROR sans adresse alors que les publics en ont
		}
		return "local_fail"
	case len(pubOK) > 0:
		return "local_fail"
	case (localNX || local.Rcode == "") && pubNX > 0 && pubNX+pubErr == len(pubs):
		return "nx"
	case local.Rcode == "NOERROR" && pubErr == 0:
		return "noaddr"
	}
	return "all_fail"
}

// chooseIPs choisit les adresses à tester : résolveur de l'OS, sinon
// requête directe, sinon repli sur un résolveur public.
func chooseIPs(ans []model.DNSAnswer) (v4, v6 []string, fallback bool) {
	pick := func(a model.DNSAnswer) bool {
		if len(a.IPs()) == 0 || isSinkhole(a.IPs()) {
			return false
		}
		v4, v6 = a.A, a.AAAA
		return true
	}
	for _, label := range []string{resOS, resSystem} {
		for _, a := range ans {
			if a.Resolver == label && pick(a) {
				return v4, v6, false
			}
		}
	}
	for _, a := range ans {
		if isPublicLabel(a.Resolver) && pick(a) {
			return v4, v6, true
		}
	}
	return nil, nil, false
}

func localServer(cfg Config) string {
	if cfg.Env != nil && len(cfg.Env.DNSServers) > 0 {
		return cfg.Env.DNSServers[0]
	}
	if len(cfg.PublicResolvers) > 0 {
		return cfg.PublicResolvers[0]
	}
	return "1.1.1.1"
}

func lookupMX(ctx context.Context, cfg Config, name string) []string {
	m, _, _, err := dnsQuery(ctx, localServer(cfg), name, dns.TypeMX, dns.ClassINET)
	if err != nil {
		return nil
	}
	var mx []*dns.MX
	for _, rr := range m.Answer {
		if v, ok := rr.(*dns.MX); ok {
			mx = append(mx, v)
		}
	}
	slices.SortFunc(mx, func(a, b *dns.MX) int { return int(a.Preference) - int(b.Preference) })
	var out []string
	for _, v := range mx {
		out = append(out, fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(v.Mx, ".")))
	}
	return out
}

func isMXHost(mx []string, name string) bool {
	for _, m := range mx {
		f := strings.Fields(m)
		if len(f) > 0 && strings.EqualFold(f[len(f)-1], name) {
			return true
		}
	}
	return false
}

func srvNames(t model.Target) []string {
	switch t.Proto {
	case "imap":
		return []string{"_imaps._tcp", "_imap._tcp"}
	case "pop3":
		return []string{"_pop3s._tcp", "_pop3._tcp"}
	case "smtp":
		return []string{"_submissions._tcp", "_submission._tcp"}
	case "ldap":
		return []string{"_ldap._tcp"}
	}
	return nil
}

func lookupSRV(ctx context.Context, cfg Config, prefixes []string, name string) []string {
	if net.ParseIP(name) != nil {
		return nil
	}
	var out []string
	for _, p := range prefixes {
		m, _, _, err := dnsQuery(ctx, localServer(cfg), p+"."+name, dns.TypeSRV, dns.ClassINET)
		if err != nil {
			continue
		}
		for _, rr := range m.Answer {
			if v, ok := rr.(*dns.SRV); ok {
				out = append(out, fmt.Sprintf("%s → %s:%d", p, strings.TrimSuffix(v.Target, "."), v.Port))
			}
		}
	}
	return out
}

// ---------- Tests globaux : interception DNS, NXDOMAIN ----------

func txtOf(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	for _, rr := range m.Answer {
		if v, ok := rr.(*dns.TXT); ok {
			return strings.Join(v.Txt, " ")
		}
	}
	return ""
}

func randLabel(n int) string {
	const alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alpha[int(b[i])%len(alpha)]
	}
	return string(b)
}

// DNSGlobal détecte l'interception du DNS (UDP 53 vers 1.1.1.1 / 8.8.8.8
// comparé au DoH) et la redirection des NXDOMAIN.
func DNSGlobal(ctx context.Context, cfg Config, sampleHost string) *model.DNSGlobal {
	start := time.Now()
	r := &model.DNSGlobal{}
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout()+3*time.Second)
	defer cancel()
	if sampleHost == "" || net.ParseIP(sampleHost) != nil {
		sampleHost = "www.wikipedia.org"
	}
	var (
		wg                       sync.WaitGroup
		cfUDP, cfDoH, gUDP, gDoH *dns.Msg
		cfUDPErr, cfDoHErr       error
		gUDPErr, gDoHErr         error
		popUDP, popDoH           *dns.Msg
	)
	r.NXName = "jalon-" + randLabel(14) + ".com"
	nxName2 := "jalon-" + randLabel(14) + ".net"
	var nx1, nx2 model.DNSAnswer
	var udpCmp, dohCmp model.DNSAnswer
	var adMsg *dns.Msg
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
	run(func() {
		cfUDP, _, _, cfUDPErr = dnsQuery(ctx, "1.1.1.1", "whoami.cloudflare", dns.TypeTXT, dns.ClassCHAOS)
	})
	run(func() {
		cfDoH, _, cfDoHErr = dohQuery(ctx, dohServers["1.1.1.1"], "whoami.cloudflare", dns.TypeTXT, dns.ClassCHAOS)
	})
	run(func() { popUDP, _, _, _ = dnsQuery(ctx, "1.1.1.1", "id.server", dns.TypeTXT, dns.ClassCHAOS) })
	run(func() { popDoH, _, _ = dohQuery(ctx, dohServers["1.1.1.1"], "id.server", dns.TypeTXT, dns.ClassCHAOS) })
	run(func() {
		gUDP, _, _, gUDPErr = dnsQuery(ctx, "8.8.8.8", "o-o.myaddr.l.google.com", dns.TypeTXT, dns.ClassINET)
	})
	run(func() {
		gDoH, _, gDoHErr = dohQuery(ctx, dohServers["8.8.8.8"], "o-o.myaddr.l.google.com", dns.TypeTXT, dns.ClassINET)
	})
	run(func() { nx1 = resolveAt(ctx, resSystem, localServer(cfg), r.NXName) })
	run(func() { nx2 = resolveAt(ctx, resSystem, localServer(cfg), nxName2) })
	run(func() { udpCmp = resolveAt(ctx, "1.1.1.1", "1.1.1.1", sampleHost) })
	run(func() {
		dohCmp = model.DNSAnswer{Resolver: "1.1.1.1", Server: dohServers["1.1.1.1"], Transport: "doh"}
		ra, rtt, err := dohQuery(ctx, dohServers["1.1.1.1"], sampleHost, dns.TypeA, dns.ClassINET)
		dohCmp.RTTMs = model.Ms(rtt)
		if err != nil {
			dohCmp.Error = dnsErr(err)
			return
		}
		raaaa, _, _ := dohQuery(ctx, dohServers["1.1.1.1"], sampleHost, dns.TypeAAAA, dns.ClassINET)
		fillAnswer(&dohCmp, ra, raaaa)
	})
	run(func() { adMsg, _, _, _ = dnsQuery(ctx, localServer(cfg), "cloudflare.com", dns.TypeA, dns.ClassINET) })
	wg.Wait()

	r.WhoamiCF = txtOf(cfUDP)
	r.CFPop, r.CFPopDoH = txtOf(popUDP), txtOf(popDoH)
	r.GoogleEgress, r.GoogleEgressDoH = txtIP(gUDP), txtIP(gDoH)
	r.UDPvsDoH = []model.DNSAnswer{udpCmp, dohCmp}
	r.DNSSEC = adMsg != nil && adMsg.AuthenticatedData
	whoDoH := txtOf(cfDoH)

	signals := interceptSignals(interceptInput{
		cfUDPOK: cfUDPErr == nil && r.WhoamiCF != "", cfDoHOK: cfDoHErr == nil && whoDoH != "",
		gUDPOK: gUDPErr == nil && r.GoogleEgress != "", gDoHOK: gDoHErr == nil && r.GoogleEgressDoH != "",
		popUDP: r.CFPop, popDoH: r.CFPopDoH,
		udpIPs: udpCmp.IPs(), dohIPs: dohCmp.IPs(),
		udpErr: udpCmp.Error != "", dohErr: dohCmp.Error != "",
	})
	r.Intercepted = len(signals) > 0
	for _, s := range signals {
		r.AddNote(model.Warn, s)
	}
	if ip, err := netip.ParseAddr(strings.Trim(r.WhoamiCF, `"`)); err == nil {
		r.WhoamiCF = ip.String()
	} else if ip, err := netip.ParseAddr(strings.Trim(whoDoH, `"`)); err == nil {
		r.WhoamiCF = ip.String()
	}

	for _, nx := range []model.DNSAnswer{nx1, nx2} {
		if len(nx.IPs()) > 0 {
			r.NXHijack = true
			r.NXAnswer = nx.IPs()
		}
	}
	switch {
	case cfDoHErr != nil && cfUDPErr != nil && gUDPErr != nil && gDoHErr != nil:
		r.Set(model.Warn, "dnsg.unreachable")
	case r.Intercepted:
		r.Set(model.Warn, "dnsg.intercepted")
	case r.NXHijack:
		r.Set(model.Warn, "dnsg.nxhijack", strings.Join(r.NXAnswer, ", "))
	default:
		r.Set(model.OK, "dnsg.ok")
	}
	if r.Intercepted && r.NXHijack {
		r.AddNote(model.Warn, "dnsg.nxhijack_note", strings.Join(r.NXAnswer, ", "))
	}
	if cfDoHErr != nil && gDoHErr != nil && (cfUDPErr == nil || gUDPErr == nil) {
		r.AddNote(model.Info, "dnsg.doh_blocked", shortErr(cfDoHErr))
	}
	if cfUDPErr != nil && gUDPErr != nil && (cfDoHErr == nil || gDoHErr == nil) {
		r.AddNote(model.Warn, "dnsg.udp53_blocked")
	}
	if r.CFPop != "" {
		r.AddNote(model.Info, "dnsg.cf_pop", r.CFPop)
	}
	if r.GoogleEgress != "" || r.GoogleEgressDoH != "" {
		r.AddNote(model.Info, "dnsg.google_egress", firstNonEmpty(r.GoogleEgress, "-"), firstNonEmpty(r.GoogleEgressDoH, "-"))
	}
	if r.DNSSEC {
		r.AddNote(model.Info, "dnsg.dnssec")
	}
	if r.WhoamiCF != "" {
		r.AddNote(model.Info, "dnsg.public_ip", r.WhoamiCF)
	}
	r.Elapsed(start)
	return r
}

// txtIP renvoie le premier enregistrement TXT qui est une adresse IP.
func txtIP(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	for _, rr := range m.Answer {
		if v, ok := rr.(*dns.TXT); ok {
			for _, t := range v.Txt {
				if ip, err := netip.ParseAddr(strings.TrimSpace(t)); err == nil {
					return ip.String()
				}
			}
		}
	}
	return ""
}

type interceptInput struct {
	cfUDPOK, cfDoHOK, gUDPOK, gDoHOK bool
	popUDP, popDoH                   string
	udpIPs, dohIPs                   []string
	udpErr, dohErr                   bool
}

// interceptSignals liste les indices d'interception DNS. Un résolveur
// intermédiaire qui capte l'UDP 53 ne connaît pas les noms spéciaux de
// Cloudflare (classe CHAOS) ni ne répond comme Google.
func interceptSignals(in interceptInput) []string {
	var s []string
	if !in.cfUDPOK && in.cfDoHOK {
		s = append(s, "dnsg.sig_cf_whoami")
	}
	if !in.gUDPOK && in.gDoHOK {
		s = append(s, "dnsg.sig_google")
	}
	if in.popUDP != "" && in.popDoH != "" && !strings.EqualFold(in.popUDP, in.popDoH) {
		// Des PoP différents peuvent être légitimes (anycast) : simple indice
		// s'il s'ajoute à un autre.
		if len(s) > 0 {
			s = append(s, "dnsg.sig_pop")
		}
	}
	// Réponses différentes entre UDP et DoH : les CDN font tourner leurs
	// adresses, donc on compare par réseau (/24, /48) et seulement en
	// complément d'un autre indice.
	if len(s) > 0 && !in.udpErr && !in.dohErr && len(in.udpIPs) > 0 && len(in.dohIPs) > 0 && !intersectsNet(in.udpIPs, in.dohIPs) {
		s = append(s, "dnsg.sig_answers")
	}
	return s
}
