package report

import (
	"fmt"
	"strings"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

// Ticket produit un résumé de 5 à 10 lignes en texte brut, prêt à coller
// dans un ticket.
func Ticket(rep *model.Report, t *model.TargetReport) string {
	l := rep.Lang
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	host, ip, gw := "-", "-", "-"
	if e := rep.Env; e != nil {
		host = firstNon(e.Hostname, "-")
		ip = firstNon(e.LocalIPv4, e.LocalIPv6, "-")
		if len(e.Gateways) > 0 {
			gw = e.Gateways[0]
		}
	}
	w("%s", i18n.T(l, "ticket.header", model.Version, fmtTime(t.Started), host, ip, gw))
	w("%s : %s", i18n.T(l, "col.target"), TargetTitle(t.Target))
	w("%s : [%s] %s", i18n.T(l, "col.verdict"), StatusText(l, t.Verdict.Status), t.Verdict.Headline.In(l))
	if len(t.Verdict.Findings) > 0 && !t.Verdict.Findings[0].Advice.IsZero() && t.Verdict.Status != model.OK {
		w("%s : %s", i18n.T(l, "ticket.advice"), t.Verdict.Findings[0].Advice.In(l))
	}
	lines := 0
	for _, s := range t.Steps() {
		if s.Status == model.Skipped || lines >= 6 {
			continue
		}
		w("- %s : %s — %s", i18n.T(l, s.Layer), StatusText(l, s.Status), s.Summary.In(l))
		lines++
	}
	if c := t.Compare; c != nil && len(c.Changes) > 0 {
		var parts []string
		for _, ch := range c.Changes {
			parts = append(parts, ch.Msg.In(l))
		}
		w("%s (%s) : %s", i18n.T(l, "ticket.changes"), fmtTime(c.PreviousTime), strings.Join(parts, " ; "))
	}
	return b.String()
}

func firstNon(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
