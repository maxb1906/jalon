package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

func mdEsc(s string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

// Markdown écrit le rapport en Markdown.
func Markdown(w io.Writer, rep *model.Report) {
	l := rep.Lang
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("# %s", i18n.T(l, "html.title"))
	p("")
	p("%s", i18n.T(l, "html.generated", rep.Version, fmtTime(rep.Started)))
	if rep.Technician != "" {
		p("")
		p("%s", mdEsc(i18n.T(l, "html.technician", rep.Technician)))
	}
	if is := rep.Issuer; is != nil {
		if who := strings.Join(nonEmpty(is.Company, is.Name, is.Contact), " · "); who != "" {
			p("")
			p("%s", mdEsc(who))
		}
	}
	if e := rep.Env; e != nil {
		p("")
		p("%s", mdEsc(i18n.T(l, "text.host", e.Hostname, e.OS, firstNon(e.LocalIPv4, e.LocalIPv6, "-"),
			firstNon(strings.Join(e.Gateways, ", "), "-"), firstNon(e.PublicIP, "-"))))
	}
	if len(rep.Targets) > 1 {
		p("")
		p("## %s", i18n.T(l, "text.synthesis"))
		p("")
		head := "| " + i18n.T(l, "col.target")
		sep := "|---"
		for _, c := range Columns {
			head += " | " + i18n.T(l, "col."+c)
			sep += "|---"
		}
		p("%s | %s |", head, i18n.T(l, "col.verdict"))
		p("%s|---|", sep)
		for _, t := range rep.Targets {
			if t == nil {
				continue
			}
			line := "| " + mdEsc(t.Target.Raw)
			ls := t.LayerStatus()
			for _, c := range Columns {
				line += " | " + Icon(ls[c]) + " " + shortStatus(l, ls[c])
			}
			p("%s | %s %s |", line, Icon(t.Verdict.Status), mdEsc(t.Verdict.Headline.In(l)))
		}
	}
	if gs := rep.GlobalSteps(); len(gs) > 0 {
		p("")
		p("## %s", i18n.T(l, "text.common"))
		p("")
		mdSteps(w, l, gs)
	}
	for _, t := range rep.Targets {
		if t == nil {
			continue
		}
		p("")
		p("## %s", mdEsc(TargetTitle(t.Target)))
		p("")
		p("**%s : %s %s**", i18n.T(l, "col.verdict"), Icon(t.Verdict.Status), mdEsc(t.Verdict.Headline.In(l)))
		if len(t.Verdict.Findings) > 0 && t.Verdict.Status != model.OK && !t.Verdict.Findings[0].Advice.IsZero() {
			p("")
			p("> %s", mdEsc(t.Verdict.Findings[0].Advice.In(l)))
		}
		for i, f := range t.Verdict.Findings {
			if i == 0 && t.Verdict.Status != model.OK {
				continue
			}
			p("- %s %s", Icon(f.Severity), mdEsc(f.Msg.In(l)))
		}
		p("")
		mdSteps(w, l, t.Steps())
		for _, tr := range t.Traces {
			if !tr.Available || len(tr.Hops) == 0 {
				continue
			}
			p("")
			p("### %s", i18n.T(l, "layer.trace_"+tr.Mode))
			p("")
			p("| # | %s | %s | min | %s | max | %s |", i18n.T(l, "hop.host"), i18n.T(l, "hop.loss"), i18n.T(l, "hop.avg"), i18n.T(l, "hop.jitter"))
			p("|---|---|---|---|---|---|---|")
			for _, h := range tr.Hops {
				name := firstNon(h.Addr, "*")
				if h.Name != "" {
					name = h.Name + " (" + h.Addr + ")"
				}
				if h.Recv == 0 {
					p("| %d | %s | %.0f %% | - | - | - | - |", h.TTL, mdEsc(name), h.LossPct)
					continue
				}
				p("| %d | %s | %.0f %% | %.1f | %.1f | %.1f | %.1f |", h.TTL, mdEsc(name), h.LossPct, h.MinMs, h.AvgMs, h.MaxMs, h.JitterMs)
			}
		}
		if c := t.Compare; c != nil {
			p("")
			p("### %s", i18n.T(l, "text.changes", fmtTime(c.PreviousTime)))
			p("")
			if len(c.Changes) == 0 {
				p("%s", i18n.T(l, "text.no_changes"))
			}
			for _, ch := range c.Changes {
				p("- %s %s", Icon(ch.Severity), mdEsc(ch.Msg.In(l)))
			}
		}
		p("")
		p("### %s", i18n.T(l, "text.ticket"))
		p("")
		p("```")
		fmt.Fprint(w, Ticket(rep, t))
		p("```")
	}
	if rep.Issuer != nil && rep.Issuer.Legal != "" {
		p("")
		p("%s", mdEsc(rep.Issuer.Legal))
	}
}

func mdSteps(w io.Writer, l i18n.Lang, steps []model.Step) {
	fmt.Fprintf(w, "| | %s | %s |\n|---|---|---|\n", i18n.T(l, "html.layer"), i18n.T(l, "html.result"))
	for _, s := range steps {
		cell := mdEsc(s.Summary.In(l))
		for _, n := range s.Notes {
			cell += "<br>" + Icon(n.Status) + " " + mdEsc(n.Msg.In(l))
		}
		fmt.Fprintf(w, "| %s | %s | %s |\n", Icon(s.Status), i18n.T(l, s.Layer), cell)
	}
}

// nonEmpty renvoie les chaînes non vides, dans l'ordre.
func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
