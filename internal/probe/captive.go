package probe

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/maxb1906/jalon/internal/model"
)

type captiveSpec struct {
	url    string
	code   int    // code attendu
	body   string // contenu attendu (sous-chaîne), vide = corps vide
	expect string
}

// Sondes de portail captif standard (Google, Microsoft, Apple).
var captiveSpecs = []captiveSpec{
	{"http://connectivitycheck.gstatic.com/generate_204", 204, "", "HTTP 204"},
	{"http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test", "200 « Microsoft Connect Test »"},
	{"http://captive.apple.com/hotspot-detect.html", 200, "Success", "200 « Success »"},
}

// Adresses de documentation (RFC 5737) : jamais routées sur Internet. Si une
// connexion TCP 80 y aboutit, un équipement intercepte le trafic.
var testNetAddrs = []string{"192.0.2.1", "198.51.100.1"}

// Captive exécute les sondes de portail captif et les heuristiques globales
// de proxy transparent.
func Captive(ctx context.Context, cfg Config) *model.CaptiveResult {
	start := time.Now()
	r := &model.CaptiveResult{}
	defer r.Elapsed(start)
	ctx, cancel := cfg.stepCtx(ctx)
	defer cancel()
	client := &http.Client{
		Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: cfg.timeout()},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	r.Checks = make([]model.CaptiveCheck, len(captiveSpecs))
	var wg sync.WaitGroup
	for i, s := range captiveSpecs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Checks[i] = runCaptive(ctx, client, s)
		}()
	}
	var testNet []string
	var tmu sync.Mutex
	for _, ip := range testNetAddrs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s := testNetHTTP(ctx, ip); s != "" {
				tmu.Lock()
				testNet = append(testNet, s)
				tmu.Unlock()
			}
		}()
	}
	wg.Wait()
	r.TestNetHTTP = testNet
	for _, c := range r.Checks {
		for _, h := range c.Headers {
			if containsFold(proxyHeaders, h.Label) && !strings.EqualFold(h.Label, "X-Cache") && !isCDNValue(h.Value) {
				r.ProxyHeaders = append(r.ProxyHeaders, model.KV{Label: h.Label, Value: h.Value + " (" + hostOf(c.URL) + ")"})
			}
		}
	}
	r.Captive = classifyCaptive(r.Checks)
	r.TransparentProxy = "no"
	switch {
	case len(r.TestNetHTTP) > 0:
		r.TransparentProxy = "probable"
	case len(r.ProxyHeaders) > 0:
		r.TransparentProxy = "check"
	}

	var bad []string
	for _, c := range r.Checks {
		if !c.Match && c.Error == "" {
			d := fmt.Sprintf("%s → %d", hostOf(c.URL), c.Status)
			if c.Location != "" {
				d += " → " + c.Location
			}
			bad = append(bad, d)
		}
	}
	switch r.Captive {
	case "probable":
		r.Set(model.Warn, "captive.probable", strings.Join(bad, " ; "))
	case "unknown":
		r.Set(model.Warn, "captive.unreachable")
	case "check":
		r.Set(model.Info, "captive.check", strings.Join(bad, " ; "))
	default:
		r.Set(model.OK, "captive.none")
	}
	switch r.TransparentProxy {
	case "probable":
		if r.Status == model.OK {
			r.Set(model.Warn, "captive.testnet", strings.Join(r.TestNetHTTP, ", "))
		} else {
			r.AddNote(model.Warn, "captive.testnet", strings.Join(r.TestNetHTTP, ", "))
		}
	case "check":
		var hs []string
		for _, h := range r.ProxyHeaders {
			hs = append(hs, h.Label+": "+h.Value)
		}
		r.AddNote(model.Warn, "captive.proxy_headers", strings.Join(hs, " ; "))
		if r.Status == model.OK {
			r.Status = model.Warn
		}
	}
	for _, c := range r.Checks {
		if c.Error != "" {
			r.AddNote(model.Info, "captive.check_error", hostOf(c.URL), c.Error)
		}
	}
	return r
}

// Signatures de CDN légitimes devant les sondes captives (Apple passe par
// son propre CDN, qui ajoute un en-tête Via).
var cdnSignatures = []string{"apple.com", "acdn", "akamai", "cloudfront", "fastly", "varnish", "google", "azureedge", "msedge"}

func isCDNValue(v string) bool {
	l := strings.ToLower(v)
	for _, s := range cdnSignatures {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	if i := strings.IndexByte(u, '/'); i >= 0 {
		u = u[:i]
	}
	return u
}

func runCaptive(ctx context.Context, client *http.Client, s captiveSpec) model.CaptiveCheck {
	c := model.CaptiveCheck{URL: s.url, Expected: s.expect}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		c.Error = err.Error()
		return c
	}
	req.Header.Set("User-Agent", UserAgent())
	resp, err := client.Do(req)
	if err != nil {
		c.Error = shortErr(err)
		return c
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	c.Status = resp.StatusCode
	c.Location = resp.Header.Get("Location")
	c.Headers = pickHeaders(resp.Header, proxyHeaders)
	c.Match = captiveMatch(s, resp.StatusCode, string(body))
	return c
}

// captiveMatch compare la réponse à l'attendu.
func captiveMatch(s captiveSpec, code int, body string) bool {
	if code != s.code {
		return false
	}
	if s.body == "" {
		return len(strings.TrimSpace(body)) == 0
	}
	return strings.Contains(body, s.body)
}

// classifyCaptive conclut à partir d'au moins deux sources.
func classifyCaptive(checks []model.CaptiveCheck) string {
	match, mismatch, errs := 0, 0, 0
	for _, c := range checks {
		switch {
		case c.Error != "":
			errs++
		case c.Match:
			match++
		default:
			mismatch++
		}
	}
	switch {
	case mismatch >= 2:
		return "probable"
	case errs == len(checks):
		return "unknown"
	case mismatch == 1:
		return "check"
	case match >= 1:
		return "no"
	}
	return "unknown"
}

// testNetHTTP tente une connexion TCP 80 vers une adresse non routable.
func testNetHTTP(ctx context.Context, ip string) string {
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip, "80"))
	if err != nil {
		return ""
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n", ip, UserAgent())
	buf := make([]byte, 512)
	n, _ := c.Read(buf)
	line := strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
	if line == "" {
		return ip + " (TCP)"
	}
	return ip + " (" + line + ")"
}

// ---------- Heuristiques de proxy transparent par cible ----------

// Proxy croise plusieurs indices locaux de proxy transparent pour une cible.
// Toujours formulé « probable » ou « à vérifier ».
func Proxy(ctx context.Context, cfg Config, t model.Target, ip string, h *model.HTTPResult, traces []*model.TraceResult) *model.ProxyResult {
	start := time.Now()
	r := &model.ProxyResult{Suspicion: "no"}
	defer r.Elapsed(start)
	ctx, cancel := cfg.stepCtx(ctx)
	defer cancel()
	var signals []string
	strong := false

	// 1. En-têtes de proxy dans la réponse.
	if h != nil {
		for _, kv := range h.Headers {
			if containsFold(proxyHeaders, kv.Label) {
				r.Headers = append(r.Headers, kv)
			}
		}
	}
	for _, kv := range r.Headers {
		if strings.EqualFold(kv.Label, "X-Cache") {
			r.AddNote(model.Info, "proxy.xcache", kv.Value)
			continue
		}
		signals = append(signals, kv.Label)
		r.AddNote(model.Warn, "proxy.header", kv.Label, kv.Value)
	}

	// 2. Délai TCP vs latence ICMP vers la même IP.
	dst, _ := netip.ParseAddr(ip)
	var icmpMin time.Duration
	var icmpTTL int
	if cfg.priv().ICMPTrace && dst.IsValid() {
		if p, _, err := newICMPProber(cfg.priv(), dst.Is6()); err == nil {
			_, recv, rtts, ttl := ping(ctx, p, dst, 3, time.Second)
			p.Close()
			if recv > 0 {
				icmpMin = slicesMin(rtts)
				icmpTTL = ttl
			}
		}
	}
	var tcpMin time.Duration
	for range 3 {
		c, d, err := dialIP(ctx, ip, t.Port)
		if err != nil {
			break
		}
		c.Close()
		if tcpMin == 0 || d < tcpMin {
			tcpMin = d
		}
	}
	r.TCP80Ms, r.ICMPMs = model.Ms(tcpMin), model.Ms(icmpMin)
	if icmpMin > 0 && tcpMin > 0 && tcpMin*2 < icmpMin && icmpMin-tcpMin > 5*time.Millisecond {
		strong = true
		signals = append(signals, "rtt")
		r.AddNote(model.Warn, "proxy.rtt", t.Port, ms1(r.TCP80Ms), ms1(r.ICMPMs))
	} else if icmpMin > 0 && tcpMin > 0 {
		r.AddNote(model.Info, "proxy.rtt_ok", t.Port, ms1(r.TCP80Ms), ms1(r.ICMPMs))
	}

	// 3. TTL du SYN-ACK comparé à la distance mesurée par le traceroute.
	traceHops := 0
	for _, tr := range traces {
		if tr != nil && tr.Reached {
			for _, hop := range tr.Hops {
				if hop.Reached {
					traceHops = hop.TTL
					break
				}
			}
			break
		}
	}
	r.TraceHops = traceHops
	if cfg.priv().RawSniffTTL && dst.IsValid() && dst.Is4() {
		if ttl := synAckTTL(ctx, dst, t.Port); ttl > 0 {
			r.SynAckTTL = ttl
			r.SynAckHops = initialTTL(ttl) - ttl + 1
		}
	}
	if r.SynAckHops > 0 && traceHops > 0 {
		if traceHops-r.SynAckHops >= 3 {
			strong = true
			signals = append(signals, "ttl")
			r.AddNote(model.Warn, "proxy.ttl", r.SynAckHops, traceHops)
		} else {
			r.AddNote(model.Info, "proxy.ttl_ok", r.SynAckHops, traceHops)
		}
	} else if icmpTTL > 0 && traceHops > 0 {
		r.AddNote(model.Info, "proxy.icmp_ttl", initialTTL(icmpTTL)-icmpTTL+1, traceHops)
	}
	if !cfg.priv().RawSniffTTL {
		r.AddNote(model.Info, "proxy.ttl_unavailable")
	}

	switch {
	case strong:
		r.Suspicion = "probable"
		r.Set(model.Warn, "proxy.probable", strings.Join(signals, ", "))
	case len(signals) > 0:
		r.Suspicion = "check"
		r.Set(model.Info, "proxy.check", strings.Join(signals, ", "))
	default:
		r.Set(model.OK, "proxy.none")
	}
	return r
}

func slicesMin(d []time.Duration) time.Duration {
	m := d[0]
	for _, v := range d {
		m = min(m, v)
	}
	return m
}

// initialTTL devine le TTL initial (64, 128 ou 255) d'un paquet reçu.
func initialTTL(ttl int) int {
	switch {
	case ttl <= 64:
		return 64
	case ttl <= 128:
		return 128
	}
	return 255
}

// synAckTTL capture (socket raw TCP, Linux root) le TTL du SYN-ACK reçu en
// réponse à une connexion vers dst:port.
func synAckTTL(ctx context.Context, dst netip.Addr, port int) int {
	pc, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return 0
	}
	defer pc.Close()
	p := ipv4.NewPacketConn(pc)
	_ = p.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc, true)
	c, _, err := dialIP(ctx, dst.String(), port)
	if err != nil {
		return 0
	}
	lport := c.LocalAddr().(*net.TCPAddr).Port
	defer c.Close()
	_ = p.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 1500)
	for {
		n, cm, src, err := p.ReadFrom(buf)
		if err != nil {
			return 0
		}
		if n < 14 || cm == nil || addrOf(src) != dst {
			continue
		}
		sp := int(buf[0])<<8 | int(buf[1])
		dp := int(buf[2])<<8 | int(buf[3])
		flags := buf[13]
		if sp == port && dp == lport && flags&0x12 == 0x12 {
			return cm.TTL
		}
	}
}
