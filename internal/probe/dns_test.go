package probe

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/maxb1906/jalon/internal/model"
)

func ans(label string, ips []string, rcode, err string) model.DNSAnswer {
	a := model.DNSAnswer{Resolver: label, Rcode: rcode, Error: err}
	for _, ip := range ips {
		if IsV6(ip) {
			a.AAAA = append(a.AAAA, ip)
		} else {
			a.A = append(a.A, ip)
		}
	}
	return a
}

func TestClassifyDNS(t *testing.T) {
	ok := "NOERROR"
	cases := []struct {
		name string
		in   []model.DNSAnswer
		want string
	}{
		{"same", []model.DNSAnswer{ans("system", []string{"1.2.3.4"}, ok, ""), ans("1.1.1.1", []string{"1.2.3.4"}, ok, ""), ans("8.8.8.8", []string{"1.2.3.4"}, ok, "")}, "same"},
		{"cdn même /24", []model.DNSAnswer{ans("system", []string{"1.2.3.4"}, ok, ""), ans("1.1.1.1", []string{"1.2.3.9"}, ok, "")}, "cdn"},
		{"cdn publics en désaccord", []model.DNSAnswer{ans("system", []string{"5.5.5.5"}, ok, ""), ans("1.1.1.1", []string{"1.2.3.4"}, ok, ""), ans("8.8.8.8", []string{"9.9.9.9"}, ok, "")}, "cdn"},
		{"differs", []model.DNSAnswer{ans("system", []string{"10.0.0.1"}, ok, ""), ans("1.1.1.1", []string{"1.2.3.4"}, ok, ""), ans("8.8.8.8", []string{"1.2.3.4"}, ok, "")}, "differs"},
		{"sinkhole", []model.DNSAnswer{ans("system", []string{"0.0.0.0"}, ok, ""), ans("1.1.1.1", []string{"1.2.3.4"}, ok, "")}, "sinkhole"},
		{"local_nx", []model.DNSAnswer{ans("system", nil, "NXDOMAIN", ""), ans("os", nil, "NXDOMAIN", ""), ans("1.1.1.1", []string{"1.2.3.4"}, ok, "")}, "local_nx"},
		{"local_fail", []model.DNSAnswer{ans("system", nil, "", "timeout"), ans("os", nil, "", "timeout"), ans("1.1.1.1", []string{"1.2.3.4"}, ok, "")}, "local_fail"},
		{"local servfail", []model.DNSAnswer{ans("system", nil, "SERVFAIL", ""), ans("1.1.1.1", []string{"1.2.3.4"}, ok, "")}, "local_fail"},
		{"os rattrape", []model.DNSAnswer{ans("system", nil, "", "timeout"), ans("os", []string{"1.2.3.4"}, ok, ""), ans("1.1.1.1", []string{"1.2.3.4"}, ok, "")}, "same"},
		{"internal", []model.DNSAnswer{ans("system", []string{"10.1.1.1"}, ok, ""), ans("1.1.1.1", nil, "NXDOMAIN", ""), ans("8.8.8.8", nil, "NXDOMAIN", "")}, "internal"},
		{"public_fail", []model.DNSAnswer{ans("system", []string{"1.2.3.4"}, ok, ""), ans("1.1.1.1", nil, "", "timeout")}, "public_fail"},
		{"nx", []model.DNSAnswer{ans("system", nil, "NXDOMAIN", ""), ans("1.1.1.1", nil, "NXDOMAIN", ""), ans("8.8.8.8", nil, "NXDOMAIN", "")}, "nx"},
		{"noaddr", []model.DNSAnswer{ans("system", nil, ok, ""), ans("1.1.1.1", nil, ok, "")}, "noaddr"},
		{"all_fail", []model.DNSAnswer{ans("system", nil, "", "timeout"), ans("1.1.1.1", nil, "", "timeout")}, "all_fail"},
	}
	for _, c := range cases {
		if got := classifyDNS(c.in); got != c.want {
			t.Errorf("%s : %s, attendu %s", c.name, got, c.want)
		}
	}
}

func TestChooseIPs(t *testing.T) {
	v4, _, fb := chooseIPs([]model.DNSAnswer{ans("system", nil, "", "timeout"), ans("os", nil, "", "timeout"), ans("1.1.1.1", []string{"1.2.3.4"}, "NOERROR", "")})
	if !fb || len(v4) != 1 || v4[0] != "1.2.3.4" {
		t.Errorf("repli public attendu : %v %v", v4, fb)
	}
	v4, v6, fb := chooseIPs([]model.DNSAnswer{ans("os", []string{"5.6.7.8", "2001:db8::1"}, "NOERROR", ""), ans("1.1.1.1", []string{"1.2.3.4"}, "NOERROR", "")})
	if fb || v4[0] != "5.6.7.8" || v6[0] != "2001:db8::1" {
		t.Errorf("OS attendu : %v %v %v", v4, v6, fb)
	}
	v4, _, fb = chooseIPs([]model.DNSAnswer{ans("system", []string{"0.0.0.0"}, "NOERROR", ""), ans("8.8.8.8", []string{"1.2.3.4"}, "NOERROR", "")})
	if !fb || v4[0] != "1.2.3.4" {
		t.Errorf("sinkhole ignoré attendu : %v", v4)
	}
}

func TestInterceptSignals(t *testing.T) {
	if s := interceptSignals(interceptInput{cfUDPOK: true, cfDoHOK: true, gUDPOK: true, gDoHOK: true}); len(s) != 0 {
		t.Errorf("aucun indice attendu : %v", s)
	}
	s := interceptSignals(interceptInput{cfUDPOK: false, cfDoHOK: true, gUDPOK: true, gDoHOK: true, udpIPs: []string{"1.1.1.1"}, dohIPs: []string{"9.9.9.9"}})
	if len(s) != 2 || s[0] != "dnsg.sig_cf_whoami" || s[1] != "dnsg.sig_answers" {
		t.Errorf("indices = %v", s)
	}
	// Réponses différentes seules (CDN) : pas d'interception.
	if s := interceptSignals(interceptInput{cfUDPOK: true, cfDoHOK: true, gUDPOK: true, gDoHOK: true, udpIPs: []string{"1.1.1.1"}, dohIPs: []string{"9.9.9.9"}}); len(s) != 0 {
		t.Errorf("CDN seul ne doit pas suffire : %v", s)
	}
	if s := interceptSignals(interceptInput{cfUDPOK: true, cfDoHOK: true, gUDPOK: false, gDoHOK: true}); len(s) != 1 || s[0] != "dnsg.sig_google" {
		t.Errorf("google = %v", s)
	}
}

func TestShortList(t *testing.T) {
	if s := shortList([]string{"a", "b", "c"}, 2); s != "a, b (+1)" {
		t.Error(s)
	}
}

// fakeDNS démarre un serveur DNS local sur un port aléatoire.
func fakeDNS(t *testing.T, h dns.HandlerFunc) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	time.Sleep(20 * time.Millisecond)
	return pc.LocalAddr().String()
}

func TestResolveAt(t *testing.T) {
	addr := fakeDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch {
		case q.Name == "absent.test.":
			m.Rcode = dns.RcodeNameError
		case q.Qtype == dns.TypeA:
			m.Answer = append(m.Answer,
				&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: 1, Ttl: 300}, Target: "cible.test."},
				&dns.A{Hdr: dns.RR_Header{Name: "cible.test.", Rrtype: dns.TypeA, Class: 1, Ttl: 60}, A: net.ParseIP("192.0.2.10")})
		case q.Qtype == dns.TypeAAAA:
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: 1, Ttl: 120}, AAAA: net.ParseIP("2001:db8::10")})
		}
		w.WriteMsg(m)
	})
	ctx := context.Background()
	a := resolveAt(ctx, "system", addr, "www.test")
	if a.Error != "" || a.Rcode != "NOERROR" || len(a.A) != 1 || a.A[0] != "192.0.2.10" || a.AAAA[0] != "2001:db8::10" || a.CNAME[0] != "cible.test" || a.TTL != 60 {
		t.Errorf("réponse = %+v", a)
	}
	nx := resolveAt(ctx, "system", addr, "absent.test")
	if nx.Rcode != "NXDOMAIN" || len(nx.IPs()) != 0 {
		t.Errorf("nx = %+v", nx)
	}
	// Serveur muet : timeout.
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	to := resolveAt(cctx, "system", pc.LocalAddr().String(), "www.test")
	if to.Error == "" {
		t.Errorf("erreur attendue : %+v", to)
	}
}

func TestDNSProbeLocal(t *testing.T) {
	addr := fakeDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: 1, Ttl: 60}, A: net.ParseIP("192.0.2.10")})
		}
		w.WriteMsg(m)
	})
	cfg := DefaultConfig()
	cfg.Timeout = 2 * time.Second
	cfg.PublicResolvers = []string{addr}
	cfg.Env = &model.EnvResult{DNSServers: []string{addr}}
	r := DNS(context.Background(), cfg, model.Target{Host: "jalon-test.invalid", Proto: "https", Port: 443})
	if r.Verdict != "same" || r.Status != model.OK || len(r.IPv4) != 1 {
		t.Errorf("DNS = %s %s %v", r.Verdict, r.Status, r.IPv4)
	}
}
