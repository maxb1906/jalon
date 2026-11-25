package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/maxb1906/jalon/internal/model"
)

func TestTCPProbe(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := DefaultConfig()
	cfg.Timeout = time.Second
	r := TCP(context.Background(), cfg, "ipv4", []string{"127.0.0.1"}, port)
	if r.Outcome != tcpConnected || r.Status != model.OK {
		t.Errorf("connecté attendu : %+v", r)
	}
	// Port fermé : refus.
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l2.Addr().(*net.TCPAddr).Port
	l2.Close()
	r = TCP(context.Background(), cfg, "ipv4", []string{"127.0.0.1"}, closed)
	if r.Outcome != tcpRefused || r.Status != model.Fail {
		t.Errorf("refus attendu : %+v", r)
	}
	// Pas d'adresse / pas d'IPv6 local.
	if r := TCP(context.Background(), cfg, "ipv6", nil, 443); r.Outcome != tcpNoAddress || r.Status != model.Skipped {
		t.Errorf("%+v", r)
	}
	cfg.Env = &model.EnvResult{}
	if r := TCP(context.Background(), cfg, "ipv6", []string{"2001:db8::1"}, 443); r.Outcome != tcpNoLocal {
		t.Errorf("%+v", r)
	}
}

func TestClassifyDialErr(t *testing.T) {
	if classifyDialErr(nil) != tcpConnected || classifyDialErr(context.DeadlineExceeded) != tcpTimeout || classifyDialErr(fmt.Errorf("x")) != tcpError {
		t.Error("classification")
	}
}

func TestTCPAdjust(t *testing.T) {
	v4 := &model.TCPResult{Family: "ipv4", Outcome: tcpConnected, Base: model.Base{Status: model.OK}}
	v6 := &model.TCPResult{Family: "ipv6", Outcome: tcpTimeout, Base: model.Base{Status: model.Fail}}
	TCPAdjust(v4, v6)
	if v6.Status != model.Warn || len(v6.Notes) != 1 {
		t.Errorf("%+v", v6)
	}
}

func targetFor(t *testing.T, raw string) model.Target {
	u := strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
	host, ps, _ := net.SplitHostPort(strings.SplitN(u, "/", 2)[0])
	port, _ := strconv.Atoi(ps)
	proto := "http"
	if strings.HasPrefix(raw, "https") {
		proto = "https"
	}
	path := "/"
	if i := strings.Index(u, "/"); i >= 0 {
		path = u[i:]
	}
	return model.Target{Raw: raw, Host: host, Port: port, Proto: proto, Path: path, IsIP: true}
}

func TestHTTPProbe(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":8443"; ma=86400`)
		w.Header().Set("Server", "jalon-test")
		w.Header().Set("Via", "1.1 squid")
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("/err", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	mux.HandleFunc("/forbidden", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	tg := targetFor(t, srv.URL+"/")
	r := HTTP(context.Background(), cfg, tg, "127.0.0.1", 1.5)
	if r.Status != model.OK || r.Code != 200 || len(r.Redirects) != 1 || !r.H3Advertised || r.H3Port != 8443 || r.Timings.DNSMs != 1.5 || r.Timings.TotalMs <= 0 {
		t.Errorf("%+v", r)
	}
	if !strings.HasPrefix(r.Proto, "HTTP/") {
		t.Errorf("proto %q", r.Proto)
	}
	var via bool
	for _, h := range r.Headers {
		via = via || h.Label == "Via"
	}
	if !via {
		t.Error("Via attendu")
	}
	if r := HTTP(context.Background(), cfg, targetFor(t, srv.URL+"/err"), "127.0.0.1", 0); r.Status != model.Fail || r.Code != 503 {
		t.Errorf("503 : %+v", r)
	}
	if r := HTTP(context.Background(), cfg, targetFor(t, srv.URL+"/forbidden"), "127.0.0.1", 0); r.Status != model.Warn {
		t.Errorf("403 : %+v", r)
	}
	// Serveur qui accepte puis se tait.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(3 * time.Second); c.Close() }()
		}
	}()
	cfg.Timeout = 500 * time.Millisecond
	mt := model.Target{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Proto: "http", Path: "/", IsIP: true}
	if r := HTTP(context.Background(), cfg, mt, "127.0.0.1", 0); r.Status != model.Fail || r.ErrorKind != "timeout" {
		t.Errorf("timeout : %+v", r)
	}
}

func TestParseAltSvc(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		port int
	}{
		{`h3=":443"; ma=86400, h3-29=":443"`, true, 443},
		{`h3-29=":443", h3="alt.example:8443"`, true, 8443},
		{`h2=":443"`, false, 0},
		{``, false, 0},
		{`h3=""`, true, 443},
	}
	for _, c := range cases {
		ok, p := parseAltSvc(c.in, 443)
		if ok != c.ok || p != c.port {
			t.Errorf("%q → %v %d", c.in, ok, p)
		}
	}
}

func TestHTTP3Probe(t *testing.T) {
	now := time.Now()
	p := newPKI(t, "Jalon H3 Root")
	l := mkCert(t, "localhost", p.inter, false, now.Add(-time.Hour), now.Add(100*24*time.Hour), nil, 0)
	cert := tls.Certificate{Certificate: [][]byte{l.cert.Raw, p.inter.cert.Raw}, PrivateKey: l.key}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	srv := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "h3") }),
	}
	go srv.Serve(udp)
	defer srv.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	tg := model.Target{Host: "localhost", Port: port, Proto: "https", Path: "/"}
	r := HTTP3(context.Background(), cfg, tg, "127.0.0.1", true, port)
	if !r.OK || r.Code != 200 || r.Status != model.OK {
		t.Errorf("%+v", r)
	}
	// Port UDP sans serveur : bloqué.
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dp := dead.LocalAddr().(*net.UDPAddr).Port
	dead.Close()
	cfg.Timeout = 700 * time.Millisecond
	r = HTTP3(context.Background(), cfg, tg, "127.0.0.1", true, dp)
	if r.OK || r.Status != model.Warn || r.Summary.Key != "http3.blocked" {
		t.Errorf("bloqué attendu : %+v", r)
	}
	if r := HTTP3(context.Background(), cfg, tg, "127.0.0.1", false, 0); r.Status != model.Skipped {
		t.Errorf("non annoncé : %+v", r)
	}
	_ = x509.NewCertPool
}

func mkHops(spec string) []model.Hop {
	// "addr:loss" séparés par des espaces ; addr "*" = muet ; suffixe "!" = destination.
	var hops []model.Hop
	for i, f := range strings.Fields(spec) {
		a, l, _ := strings.Cut(f, ":")
		loss, _ := strconv.ParseFloat(strings.TrimSuffix(l, "!"), 64)
		h := model.Hop{TTL: i + 1, Sent: 10, LossPct: loss, Recv: int(10 - loss/10), AvgMs: 10}
		if a == "*" {
			h.Recv, h.LossPct, a = 0, 100, ""
		}
		h.Addr = a
		h.Reached = strings.HasSuffix(l, "!")
		hops = append(hops, h)
	}
	return hops
}

func TestAnalyzeTrace(t *testing.T) {
	cases := []struct {
		name, hops string
		key        string
		lossFrom   int
		loop       bool
	}{
		{"ok", "10.0.0.1:0 1.1.1.1:0 9.9.9.9:0!", "trace.ok", 0, false},
		{"perte isolée", "10.0.0.1:0 1.1.1.1:60 2.2.2.2:0 9.9.9.9:0!", "trace.ok", 0, false},
		{"perte propagée", "10.0.0.1:0 1.1.1.1:0 2.2.2.2:40 3.3.3.3:40 9.9.9.9:40!", "trace.loss", 3, false},
		{"saut muet", "10.0.0.1:0 *:100 2.2.2.2:0 9.9.9.9:0!", "trace.ok", 0, false},
		{"non atteinte", "10.0.0.1:0 1.1.1.1:0 *:100 *:100", "trace.not_reached", 0, false},
		{"aucune réponse", "*:100 *:100", "trace.no_response", 0, false},
		{"boucle", "10.0.0.1:0 1.1.1.1:0 2.2.2.2:0 1.1.1.1:0 2.2.2.2:0", "trace.loop", 0, true},
	}
	for _, c := range cases {
		r := &model.TraceResult{Available: true, Mode: "icmp", Dest: "9.9.9.9", Hops: mkHops(c.hops)}
		AnalyzeTrace(r)
		if r.Summary.Key != c.key || r.LossFrom != c.lossFrom || r.Loop != c.loop {
			t.Errorf("%s : %s lossFrom=%d loop=%v", c.name, r.Summary.Key, r.LossFrom, r.Loop)
		}
	}
	r := &model.TraceResult{Available: true, Dest: "9.9.9.9", Hops: mkHops("10.0.0.1:0 *:100 9.9.9.9:0!")}
	AnalyzeTrace(r)
	if !r.Hops[1].Silent || r.LastHop != 3 {
		t.Errorf("muet : %+v", r.Hops)
	}
}

func TestCompareTraces(t *testing.T) {
	ic := &model.TraceResult{Available: true, Mode: "icmp", Hops: mkHops("10.0.0.1:0 1.1.1.1:0 *:100")}
	AnalyzeTrace(ic)
	tc := &model.TraceResult{Available: true, Mode: "tcp", Hops: mkHops("10.0.0.1:0 1.1.1.1:0 9.9.9.9:0!")}
	AnalyzeTrace(tc)
	CompareTraces([]*model.TraceResult{ic, tc})
	if ic.Status != model.Info {
		t.Errorf("ICMP filtré : %+v", ic.Base)
	}
	ic2 := &model.TraceResult{Available: true, Mode: "icmp", Hops: mkHops("10.0.0.1:0 5.5.5.5:0 6.6.6.6:0 9.9.9.9:0!")}
	tc2 := &model.TraceResult{Available: true, Mode: "tcp", Hops: mkHops("10.0.0.2:0 7.7.7.7:0 8.8.8.8:0")}
	AnalyzeTrace(ic2)
	AnalyzeTrace(tc2)
	CompareTraces([]*model.TraceResult{ic2, tc2})
	keys := ""
	for _, n := range tc2.Notes {
		keys += n.Msg.Key + " "
	}
	if !strings.Contains(keys, "trace.cmp_tcp_filtered") || !strings.Contains(keys, "trace.cmp_paths_differ") {
		t.Errorf("notes TCP : %s", keys)
	}
}

// fakeProber simule un chemin de 3 sauts avec ECMP au dernier.
type fakeProber struct{ n int }

func (f *fakeProber) Close() error { return nil }
func (f *fakeProber) Probe(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) reply {
	switch ttl {
	case 1:
		return reply{kind: rTimeExceeded, from: netip.MustParseAddr("10.0.0.1"), rtt: time.Millisecond}
	case 2:
		return reply{kind: rTimeout}
	}
	return reply{kind: rReached, from: dst, rtt: 5 * time.Millisecond}
}

func TestTracerSnapshot(t *testing.T) {
	dst := netip.MustParseAddr("192.0.2.1")
	tc := &tracer{dst: dst, prober: &fakeProber{}}
	tc.hops = make([]*hopAgg, 31)
	for i := range tc.hops {
		tc.hops[i] = &hopAgg{addrs: map[string]int{}}
	}
	for round := 0; round < 3; round++ {
		for ttl := 1; ttl <= 5; ttl++ {
			tc.record(ttl, tc.prober.Probe(context.Background(), dst, ttl, time.Second))
		}
	}
	r := tc.snapshot(&model.TraceResult{Available: true, Dest: dst.String()})
	if !r.Reached || len(r.Hops) != 3 || !r.Hops[2].Reached || r.Hops[1].Recv != 0 {
		t.Fatalf("%+v", r.Hops)
	}
	AnalyzeTrace(r)
	if r.Summary.Key != "trace.ok" {
		t.Errorf("%s", r.Summary.Key)
	}
}

func TestParseInner(t *testing.T) {
	// En-tête IPv4 (20 octets) + écho ICMP id=0x1234 seq=7.
	d := make([]byte, 28)
	d[0], d[9] = 0x45, 1
	d[20] = 8
	d[24], d[25], d[26], d[27] = 0x12, 0x34, 0, 7
	k, ok := parseInner(d, false, 0x1234, false)
	if !ok || k != (waitKey{'e', 7}) {
		t.Errorf("écho : %v %v", k, ok)
	}
	if _, ok := parseInner(d, false, 0x9999, false); ok {
		t.Error("id différent accepté")
	}
	// TCP, port source 40000.
	d[9] = 6
	d[20], d[21] = 0x9c, 0x40
	k, ok = parseInner(d, false, 0, false)
	if !ok || k != (waitKey{'t', 40000}) {
		t.Errorf("tcp : %v %v", k, ok)
	}
	if _, ok := parseInner(d[:10], false, 0, false); ok {
		t.Error("tronqué accepté")
	}
}

func TestInitialTTL(t *testing.T) {
	for in, want := range map[int]int{60: 64, 64: 64, 117: 128, 250: 255} {
		if initialTTL(in) != want {
			t.Errorf("%d", in)
		}
	}
}

func TestCaptive(t *testing.T) {
	ok204 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer ok204.Close()
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://portail.local/login", http.StatusFound)
	}))
	defer portal.Close()
	saveS, saveT := captiveSpecs, testNetAddrs
	defer func() { captiveSpecs, testNetAddrs = saveS, saveT }()
	testNetAddrs = nil
	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second

	captiveSpecs = []captiveSpec{{ok204.URL, 204, "", "204"}, {ok204.URL, 204, "", "204"}, {ok204.URL, 204, "", "204"}}
	if r := Captive(context.Background(), cfg); r.Captive != "no" || r.Status != model.OK {
		t.Errorf("aucun portail : %+v", r)
	}
	captiveSpecs = []captiveSpec{{portal.URL, 204, "", "204"}, {portal.URL, 200, "Success", "200"}, {ok204.URL, 204, "", "204"}}
	r := Captive(context.Background(), cfg)
	if r.Captive != "probable" || r.Status != model.Warn || !strings.Contains(r.Summary.Args[0], "portail.local") {
		t.Errorf("portail : %+v", r)
	}
}

func TestClassifyCaptive(t *testing.T) {
	m := func(match bool, err string) model.CaptiveCheck { return model.CaptiveCheck{Match: match, Error: err} }
	cases := map[string][]model.CaptiveCheck{
		"no":       {m(true, ""), m(true, ""), m(true, "")},
		"check":    {m(true, ""), m(false, ""), m(true, "")},
		"probable": {m(false, ""), m(false, ""), m(true, "")},
		"unknown":  {m(false, "x"), m(false, "x"), m(false, "x")},
	}
	for want, in := range cases {
		if got := classifyCaptive(in); got != want {
			t.Errorf("%s → %s", want, got)
		}
	}
	if !captiveMatch(captiveSpec{code: 200, body: "Success"}, 200, "<HTML>Success</HTML>") || captiveMatch(captiveSpec{code: 204}, 204, "portail") {
		t.Error("captiveMatch")
	}
}

func TestProxyHeuristics(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cfg := DefaultConfig()
	tg := model.Target{Host: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port, Proto: "http"}
	h := &model.HTTPResult{Headers: []model.KV{{Label: "Via", Value: "1.1 proxy.corp"}, {Label: "X-Cache", Value: "HIT"}}}
	r := Proxy(context.Background(), cfg, tg, "127.0.0.1", h, nil)
	if r.Suspicion != "check" || r.Status != model.Info {
		t.Errorf("Via : %+v", r)
	}
	r = Proxy(context.Background(), cfg, tg, "127.0.0.1", &model.HTTPResult{}, nil)
	if r.Suspicion != "no" || r.Status != model.OK {
		t.Errorf("aucun : %+v", r)
	}
}
