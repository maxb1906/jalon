package history

import (
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/model"
)

func tr(start time.Time, ips []string, fp string, tcp float64, st model.Status) *model.TargetReport {
	return &model.TargetReport{
		Target:  model.Target{Raw: "https://site.test", Host: "site.test", Port: 443, Proto: "https", Path: "/"},
		Started: start,
		DNS:     &model.DNSResult{Base: model.Base{Status: model.OK}, IPv4: ips},
		TCP:     []*model.TCPResult{{Base: model.Base{Status: st}, Family: "ipv4", Outcome: map[bool]string{true: "connected", false: "timeout"}[st == model.OK], RTTMs: tcp}},
		TLS:     &model.TLSResult{Base: model.Base{Status: model.OK}, Chain: []model.CertInfo{{SHA256: fp, Issuer: "CA", NotAfter: start.Add(90 * 24 * time.Hour)}}},
		Verdict: model.Verdict{Status: st},
	}
}

func TestStore(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env := &model.EnvResult{Gateways: []string{"10.0.0.1"}, PublicIP: "203.0.113.5"}
	other := &model.EnvResult{Gateways: []string{"192.168.1.1"}, PublicIP: "198.51.100.9"}
	t0 := time.Now().Add(-48 * time.Hour)
	id1, err := s.Save(env, tr(t0, []string{"192.0.2.1"}, "aa", 10, model.OK))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(other, tr(t0.Add(time.Hour), []string{"192.0.2.1"}, "aa", 10, model.OK)); err != nil {
		t.Fatal(err)
	}
	cur := tr(time.Now(), []string{"192.0.2.99"}, "bb", 80, model.OK)
	prev, same := s.Previous(cur.Target.Key(), NetworkKey(env), cur.Started)
	if prev == nil || !same || prev.ID != id1 {
		t.Fatalf("précédent même réseau attendu : %+v %v", prev, same)
	}
	if prev, same := s.Previous(cur.Target.Key(), "x|y", cur.Started); prev == nil || same {
		t.Errorf("repli autre réseau attendu")
	}
	if l := s.List(""); len(l) != 2 || !l[0].Time.After(l[1].Time) {
		t.Errorf("liste %+v", l)
	}
	if l := s.List("autre"); len(l) != 0 {
		t.Errorf("filtre %+v", l)
	}
	if e, err := s.Load(id1[:20]); err != nil || e.ID != id1 {
		t.Errorf("préfixe : %v", err)
	}
	n, err := s.Purge(24 * time.Hour)
	if err != nil || n != 2 || len(s.List("")) != 0 {
		t.Errorf("purge %d %v", n, err)
	}
}

func kinds(c []model.Change) map[string]model.Status {
	m := map[string]model.Status{}
	for _, x := range c {
		m[x.Kind] = x.Severity
	}
	return m
}

func TestCompare(t *testing.T) {
	now := time.Now()
	a := tr(now, []string{"192.0.2.1"}, "aa", 10, model.OK)
	b := tr(now, []string{"192.0.2.99"}, "bb", 80, model.OK)
	k := kinds(Compare(a, b))
	if _, ok := k["ips"]; !ok {
		t.Error("ips")
	}
	if _, ok := k["cert"]; !ok {
		t.Error("cert")
	}
	if k["latency"] != model.Warn {
		t.Error("latence")
	}
	c := tr(now, []string{"192.0.2.1"}, "aa", 10, model.Fail)
	if k := kinds(Compare(a, c)); k["layer"] != model.Fail {
		t.Errorf("OK → échec : %v", k)
	}
	if k := kinds(Compare(c, a)); k["layer"] != model.OK {
		t.Errorf("rétabli : %v", k)
	}
	if ch := Compare(a, a); len(ch) != 0 {
		t.Errorf("aucun changement attendu : %+v", ch)
	}
	pa := tr(now, nil, "", 0, model.OK)
	pa.Traces = []*model.TraceResult{{Mode: "icmp", Available: true, Hops: []model.Hop{{Addr: "1.1.1.1"}, {Addr: "2.2.2.2"}, {Addr: "3.3.3.3"}}}}
	pb := tr(now, nil, "", 0, model.OK)
	pb.Traces = []*model.TraceResult{{Mode: "icmp", Available: true, Hops: []model.Hop{{Addr: "1.1.1.1"}, {Addr: "8.8.8.8"}, {Addr: "9.9.9.9"}}}}
	if k := kinds(Compare(pa, pb)); k["path"] == "" {
		t.Errorf("chemin : %v", k)
	}
}

func TestSlugNetworkKey(t *testing.T) {
	if s := slug("Mail.Exemple.BE-smtp"); s != "mail-exemple-be-smtp" {
		t.Error(s)
	}
	if NetworkKey(nil) != "" || NetworkKey(&model.EnvResult{}) != "-|-" {
		t.Error("NetworkKey")
	}
}
