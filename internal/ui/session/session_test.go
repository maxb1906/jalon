package session

import (
	"strings"
	"testing"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

func TestPrepare(t *testing.T) {
	base := engine.DefaultOptions()
	ts, opt, err := Prepare(base, Request{Targets: "exemple.be, smtp://mail.exemple.be\n# commentaire\n10.0.0.5:3389", TraceMode: "icmp", NoTrace: true, IPv6: true}, "", i18n.EN)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 3 || ts[0].Proto != "https" || ts[1].Proto != "smtp" || ts[2].Proto != "rdp" {
		t.Errorf("cibles %+v", ts)
	}
	if opt.TraceMode != "icmp" || !opt.NoTrace || !opt.IPv6Only || opt.IPv4Only || opt.Lang != i18n.EN {
		t.Errorf("options %+v", opt)
	}
	if base.NoTrace {
		t.Error("options de base modifiées")
	}
	_, opt, _ = Prepare(base, Request{Targets: "a.test", IPv4: true, IPv6: true, TraceMode: "bogus"}, "ssh", i18n.FR)
	if opt.IPv4Only || opt.IPv6Only || opt.TraceMode != "auto" {
		t.Errorf("IPv4+IPv6 / mode inconnu : %+v", opt)
	}
	if ts, _, _ := Prepare(base, Request{Targets: "a.test"}, "ssh", i18n.FR); ts[0].Proto != "ssh" {
		t.Errorf("protocole par défaut : %s", ts[0].Proto)
	}
	if _, _, err := Prepare(base, Request{Targets: " \n"}, "", i18n.FR); err == nil || err.Error() != "aucune cible" {
		t.Errorf("vide : %v", err)
	}
	if _, _, err := Prepare(base, Request{Targets: "gopher://x"}, "", i18n.FR); err == nil {
		t.Error("schéma inconnu accepté")
	}
	many := strings.Repeat("a.test\n", MaxTargets+10)
	if ts, _, _ := Prepare(base, Request{Targets: many}, "", i18n.FR); len(ts) != MaxTargets {
		t.Errorf("borne : %d", len(ts))
	}
}

func TestExport(t *testing.T) {
	rep := &model.Report{Tool: "jalon", Lang: i18n.FR, Targets: []*model.TargetReport{{Target: model.Target{Raw: "a.test", Proto: "https", Host: "a.test", Port: 443}}}}
	for f, ext := range map[string]string{"html": "html", "md": "md", "ticket": "txt", "json": "json", "": "json"} {
		b, e, ct := Export(rep, f)
		if len(b) == 0 || e != ext || ct == "" {
			t.Errorf("%s : %d octets, %s, %s", f, len(b), e, ct)
		}
	}
	if !strings.Contains(Ticket(rep), "a.test") {
		t.Error("ticket sans la cible")
	}
}
