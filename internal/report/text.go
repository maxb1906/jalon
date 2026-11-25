package report

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

// Style colore la sortie terminal (codes ANSI) si activé.
type Style struct{ Color bool }

func (s Style) wrap(code, txt string) string {
	if !s.Color {
		return txt
	}
	return "\x1b[" + code + "m" + txt + "\x1b[0m"
}

// Status colore un texte selon un statut.
func (s Style) Status(st model.Status, txt string) string {
	switch st {
	case model.OK:
		return s.wrap("32", txt)
	case model.Warn:
		return s.wrap("33", txt)
	case model.Fail:
		return s.wrap("31", txt)
	case model.Info:
		return s.wrap("36", txt)
	}
	return s.wrap("2", txt)
}

// Bold met en gras.
func (s Style) Bold(txt string) string { return s.wrap("1", txt) }

// Dim atténue.
func (s Style) Dim(txt string) string { return s.wrap("2", txt) }

func pad(s string, n int) string {
	w := utf8.RuneCountInString(s)
	if w >= n {
		return s
	}
	return s + strings.Repeat(" ", n-w)
}

// TextOptions règle le rendu texte.
type TextOptions struct {
	Style   Style
	Verbose bool // notes « info » et sauts détaillés
	Ticket  bool // ajouter le résumé ticket
	Live    bool // les étapes ont déjà été affichées en direct
}

// Text écrit le rapport complet pour le terminal.
func Text(w io.Writer, rep *model.Report, o TextOptions) {
	l, st := rep.Lang, o.Style
	if !o.Live {
		fmt.Fprintln(w, st.Bold(fmt.Sprintf("Jalon %s — %s", rep.Version, fmtTime(rep.Started))))
	} else {
		fmt.Fprintln(w)
	}
	if e := rep.Env; e != nil {
		fmt.Fprintln(w, i18n.T(l, "text.host", e.Hostname, e.OS, firstNon(e.LocalIPv4, e.LocalIPv6, "-"),
			firstNon(strings.Join(e.Gateways, ", "), "-"), firstNon(e.PublicIP, "-")))
	}
	if gs := rep.GlobalSteps(); len(gs) > 0 && !o.Live {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.Bold("== "+i18n.T(l, "text.common")+" =="))
		for _, s := range gs {
			writeStep(w, l, o, s, "")
		}
	}
	for _, t := range rep.Targets {
		if t == nil {
			continue
		}
		fmt.Fprintln(w)
		TargetText(w, rep, t, o)
	}
	if len(rep.Targets) > 1 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.Bold("== "+i18n.T(l, "text.synthesis")+" =="))
		Synthesis(w, rep, st)
	}
	if o.Ticket {
		for _, t := range rep.Targets {
			if t == nil {
				continue
			}
			fmt.Fprintln(w)
			fmt.Fprintln(w, st.Bold("== "+i18n.T(l, "text.ticket")+" — "+t.Target.Raw+" =="))
			fmt.Fprint(w, Ticket(rep, t))
		}
	}
}

func writeStep(w io.Writer, l i18n.Lang, o TextOptions, s model.Step, indent string) {
	st := o.Style
	fmt.Fprintf(w, "%s%s %s %s\n", indent, st.Status(s.Status, Icon(s.Status)), pad(i18n.T(l, s.Layer), 24), s.Summary.In(l))
	for _, n := range s.Notes {
		if n.Status == model.Info && !o.Verbose {
			continue
		}
		line := fmt.Sprintf("%s    %s %s", indent, Icon(n.Status), n.Msg.In(l))
		if n.Status == model.Info {
			line = st.Dim(line)
		} else {
			line = indent + "    " + st.Status(n.Status, Icon(n.Status)) + " " + n.Msg.In(l)
		}
		fmt.Fprintln(w, line)
	}
}

// TargetText écrit le détail d'une cible.
func TargetText(w io.Writer, rep *model.Report, t *model.TargetReport, o TextOptions) {
	l, st := rep.Lang, o.Style
	fmt.Fprintln(w, st.Bold("== "+TargetTitle(t.Target)+" =="))
	v := t.Verdict
	fmt.Fprintf(w, "%s %s\n", st.Bold(i18n.T(l, "col.verdict")+" "+st.Status(v.Status, Icon(v.Status))), st.Status(v.Status, v.Headline.In(l)))
	if len(v.Findings) > 0 && !v.Findings[0].Advice.IsZero() && v.Status != model.OK {
		fmt.Fprintf(w, "  → %s\n", v.Findings[0].Advice.In(l))
	}
	for i, f := range v.Findings {
		if i == 0 && v.Status != model.OK {
			continue
		}
		fmt.Fprintf(w, "  %s %s\n", st.Status(f.Severity, Icon(f.Severity)), f.Msg.In(l))
	}
	if !o.Live {
		fmt.Fprintln(w)
		for _, s := range t.Steps() {
			writeStep(w, l, o, s, "  ")
		}
	}
	for _, tr := range t.Traces {
		if tr.Available && len(tr.Hops) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "  "+st.Bold(i18n.T(l, "layer.trace_"+tr.Mode)))
			HopsText(w, l, tr, "    ")
		}
	}
	if c := t.Compare; c != nil {
		fmt.Fprintln(w)
		title := i18n.T(l, "text.changes", fmtTime(c.PreviousTime))
		if !c.SameNetwork {
			title += " " + i18n.T(l, "text.other_network")
		}
		fmt.Fprintln(w, "  "+st.Bold(title))
		if len(c.Changes) == 0 {
			fmt.Fprintln(w, "    "+i18n.T(l, "text.no_changes"))
		}
		for _, ch := range c.Changes {
			fmt.Fprintf(w, "    %s %s\n", st.Status(ch.Severity, Icon(ch.Severity)), ch.Msg.In(l))
		}
	}
}

// HopsText écrit le tableau des sauts façon MTR.
func HopsText(w io.Writer, l i18n.Lang, tr *model.TraceResult, indent string) {
	fmt.Fprintf(w, "%s%3s  %-42s %6s %5s %8s %8s %8s %7s\n", indent, "#", i18n.T(l, "hop.host"), i18n.T(l, "hop.loss"), i18n.T(l, "hop.sent"), "min", i18n.T(l, "hop.avg"), "max", i18n.T(l, "hop.jitter"))
	for _, h := range tr.Hops {
		name := "*"
		if h.Addr != "" {
			name = h.Addr
			if h.Name != "" {
				name = h.Name + " (" + h.Addr + ")"
			}
			if h.ASN != "" {
				name += " " + h.ASN
			}
		}
		if utf8.RuneCountInString(name) > 42 {
			name = string([]rune(name)[:41]) + "…"
		}
		if h.Recv == 0 {
			fmt.Fprintf(w, "%s%3d  %-42s %5.0f%% %5d %8s %8s %8s %7s\n", indent, h.TTL, name, h.LossPct, h.Sent, "-", "-", "-", "-")
			continue
		}
		fmt.Fprintf(w, "%s%3d  %-42s %5.0f%% %5d %8.1f %8.1f %8.1f %7.1f\n", indent, h.TTL, name, h.LossPct, h.Sent, h.MinMs, h.AvgMs, h.MaxMs, h.JitterMs)
	}
}

// Synthesis écrit le tableau multi-cible.
func Synthesis(w io.Writer, rep *model.Report, st Style) {
	l := rep.Lang
	tw := utf8.RuneCountInString(i18n.T(l, "col.target"))
	for _, t := range rep.Targets {
		if t != nil {
			tw = max(tw, utf8.RuneCountInString(t.Target.Raw))
		}
	}
	tw = min(tw, 40)
	head := pad(i18n.T(l, "col.target"), tw)
	for _, c := range Columns {
		head += "  " + pad(i18n.T(l, "col."+c), 10)
	}
	fmt.Fprintln(w, head+"  "+i18n.T(l, "col.verdict"))
	for _, t := range rep.Targets {
		if t == nil {
			continue
		}
		name := t.Target.Raw
		if utf8.RuneCountInString(name) > tw {
			name = string([]rune(name)[:tw-1]) + "…"
		}
		line := pad(name, tw)
		ls := t.LayerStatus()
		for _, c := range Columns {
			s := ls[c]
			line += "  " + st.Status(s, pad(Icon(s)+" "+shortStatus(l, s), 10))
		}
		fmt.Fprintln(w, line+"  "+st.Status(t.Verdict.Status, t.Verdict.Headline.In(l)))
	}
}

func shortStatus(l i18n.Lang, s model.Status) string {
	if s == "" {
		s = model.Skipped
	}
	return i18n.T(l, "short."+string(s))
}
