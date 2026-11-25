package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

func sample(l i18n.Lang) *model.Report {
	ok := model.Base{Status: model.OK, Summary: i18n.M("tcp.connected", "192.0.2.1", 443, "12.0")}
	t := &model.TargetReport{
		Target:  model.Target{Raw: "https://site.test", Host: "site.test", Port: 443, Proto: "https"},
		Started: time.Now(),
		DNS:     &model.DNSResult{Base: model.Base{Status: model.OK, Summary: i18n.M("dns.same", "site.test", "192.0.2.1")}},
		TCP:     []*model.TCPResult{{Base: ok, Family: "ipv4"}},
		HTTP:    &model.HTTPResult{Base: model.Base{Status: model.Warn, Summary: i18n.M("http.forbidden", 403, "https://site.test/"), Notes: []model.Note{{Status: model.Info, Msg: i18n.M("http.timings", 1, 2, 3, 4, 5)}}}},
		Traces:  []*model.TraceResult{{Base: ok, Mode: "icmp", Available: true, Hops: []model.Hop{{TTL: 1, Addr: "10.0.0.1", Sent: 5, Recv: 5, AvgMs: 1}, {TTL: 2, Sent: 5}}}},
		Verdict: model.Verdict{Status: model.Warn, Headline: i18n.M("v.http_forbidden", 403),
			Findings: []model.Finding{{Rule: "http_forbidden", Severity: model.Warn, Msg: i18n.M("v.http_forbidden", 403), Advice: i18n.M("a.http_forbidden")}}},
		Compare: &model.Comparison{PreviousTime: time.Now().Add(-time.Hour), SameNetwork: true, Changes: []model.Change{{Kind: "ips", Severity: model.Info, Msg: i18n.M("chg.ips", "a", "b")}}},
	}
	t2 := *t
	t2.Target.Raw = "smtp://mail.test"
	return &model.Report{Version: "test", Lang: l, Started: time.Now(),
		Env:     &model.EnvResult{Base: ok, Hostname: "pc", OS: "linux/amd64", LocalIPv4: "10.0.0.2", Gateways: []string{"10.0.0.1"}},
		Targets: []*model.TargetReport{t, &t2}}
}

func TestJSONHasText(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample(i18n.EN)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"text": "Access denied by the server (HTTP 403)"`) {
		t.Error(b.String()[:400])
	}
	var v map[string]any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Error(err)
	}
}

func TestTicket(t *testing.T) {
	rep := sample(i18n.FR)
	s := Ticket(rep, rep.Targets[0])
	n := strings.Count(s, "\n")
	if n < 5 || n > 10 {
		t.Errorf("%d lignes :\n%s", n, s)
	}
	if !strings.Contains(s, "Accès refusé") || !strings.Contains(s, "Piste") || !strings.Contains(s, "Changements") {
		t.Error(s)
	}
}

func TestTextMarkdownHTML(t *testing.T) {
	for _, l := range []i18n.Lang{i18n.FR, i18n.EN} {
		rep := sample(l)
		var b bytes.Buffer
		Text(&b, rep, TextOptions{Ticket: true, Verbose: true})
		if !strings.Contains(b.String(), "10.0.0.1") || !strings.Contains(b.String(), i18n.T(l, "text.synthesis")) {
			t.Error(b.String())
		}
		b.Reset()
		Markdown(&b, rep)
		if !strings.Contains(b.String(), "| # |") || !strings.Contains(b.String(), "```") {
			t.Error(b.String())
		}
		b.Reset()
		if err := HTML(&b, rep); err != nil {
			t.Fatal(err)
		}
		h := b.String()
		if !strings.Contains(h, "<!doctype html>") || strings.Contains(h, "http://") && strings.Contains(h, "<link") || strings.Contains(h, "<script src") {
			t.Error("HTML autonome attendu")
		}
	}
}
