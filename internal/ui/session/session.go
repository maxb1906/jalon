// Package session regroupe ce que partagent les interfaces interactives
// (UI web locale et interface graphique) : lecture d'une demande de
// diagnostic, exports, consultation et comparaison de l'historique.
package session

import (
	"bytes"
	"errors"
	"strings"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/report"
	"github.com/maxb1906/jalon/internal/target"
)

// MaxTargets borne le nombre de cibles d'une demande interactive.
const MaxTargets = 50

// Request est une demande de diagnostic saisie dans une interface.
type Request struct {
	Targets   string `json:"targets"` // une cible par ligne (ou séparées par des virgules)
	Proto     string `json:"proto"`
	TraceMode string `json:"trace_mode"`
	NoTrace   bool   `json:"no_trace"`
	IPv4      bool   `json:"ipv4"`
	IPv6      bool   `json:"ipv6"`
	Lang      string `json:"lang"`
}

// ErrNoTarget : la demande ne contient aucune cible.
var ErrNoTarget = errors.New("no target")

// Prepare analyse les cibles de la demande et dérive les options du moteur
// de base. defProto s'applique quand la demande ne précise pas de protocole.
// Les erreurs sont déjà traduites dans la langue l.
func Prepare(base engine.Options, req Request, defProto string, l i18n.Lang) ([]model.Target, engine.Options, error) {
	raws, _ := target.ReadList(strings.NewReader(strings.ReplaceAll(req.Targets, ",", "\n")))
	if len(raws) == 0 {
		return nil, base, errors.New(i18n.T(l, "web.no_target"))
	}
	if len(raws) > MaxTargets {
		raws = raws[:MaxTargets]
	}
	proto := req.Proto
	if proto == "" {
		proto = defProto
	}
	targets := make([]model.Target, 0, len(raws))
	for _, raw := range raws {
		t, err := target.Parse(raw, proto)
		if err != nil {
			return nil, base, errors.New(i18n.T(l, "engine.target_error", raw+" : "+err.Error()))
		}
		targets = append(targets, t)
	}
	opt := base
	opt.Lang = l
	if req.NoTrace {
		opt.NoTrace = true
	}
	switch req.TraceMode {
	case "icmp", "tcp", "auto":
		opt.TraceMode = req.TraceMode
	}
	if req.IPv4 && !req.IPv6 {
		opt.IPv4Only, opt.IPv6Only = true, false
	}
	if req.IPv6 && !req.IPv4 {
		opt.IPv6Only, opt.IPv4Only = true, false
	}
	return targets, opt, nil
}

// Export rend un rapport dans un format (html, md, ticket, json par défaut)
// et renvoie le contenu, l'extension de fichier et le type MIME.
func Export(rep *model.Report, format string) ([]byte, string, string) {
	var buf bytes.Buffer
	switch format {
	case "html":
		_ = report.HTML(&buf, rep)
		return buf.Bytes(), "html", "text/html; charset=utf-8"
	case "md":
		report.Markdown(&buf, rep)
		return buf.Bytes(), "md", "text/markdown; charset=utf-8"
	case "ticket":
		return []byte(Ticket(rep)), "txt", "text/plain; charset=utf-8"
	default:
		_ = report.JSON(&buf, rep)
		return buf.Bytes(), "json", "application/json; charset=utf-8"
	}
}

// Ticket renvoie les résumés ticket de toutes les cibles.
func Ticket(rep *model.Report) string {
	var b strings.Builder
	for _, t := range rep.Targets {
		if t != nil {
			b.WriteString(report.Ticket(rep, t) + "\n")
		}
	}
	return b.String()
}

// BaseName est le nom de fichier (sans extension) proposé pour un export.
func BaseName(rep *model.Report) string {
	return "jalon-" + rep.Started.Format("20060102-150405")
}

// HistoryReport reconstitue un rapport complet à partir d'une entrée
// d'historique (une seule cible).
func HistoryReport(e *history.Entry, l i18n.Lang) *model.Report {
	rep := &model.Report{Tool: "jalon", Version: e.Version, Lang: l, Started: e.Time, Finished: e.Report.Finished,
		Env: e.Env, Targets: []*model.TargetReport{e.Report}}
	rep.ComputeExit()
	return rep
}

// HistoryItem est une ligne de la liste d'historique, verdict traduit.
type HistoryItem struct {
	history.Meta
	Text string `json:"text"`
}

// HistoryList renvoie au plus 500 entrées filtrées, les plus récentes d'abord.
func HistoryList(s *history.Store, filter string, l i18n.Lang) []HistoryItem {
	out := []HistoryItem{}
	if s == nil {
		return out
	}
	for _, m := range s.List(filter) {
		out = append(out, HistoryItem{m, m.Headline.In(l)})
		if len(out) >= 500 {
			break
		}
	}
	return out
}

// ChangeItem est une différence, message traduit.
type ChangeItem struct {
	model.Change
	Text string `json:"text"`
}

// DiffResult est la comparaison de deux diagnostics enregistrés.
type DiffResult struct {
	From        string       `json:"from"`
	To          string       `json:"to"`
	FromRaw     string       `json:"from_raw"`
	ToRaw       string       `json:"to_raw"`
	FromTime    string       `json:"from_time"`
	ToTime      string       `json:"to_time"`
	SameTarget  bool         `json:"same_target"`
	SameNetwork bool         `json:"same_network"`
	FromVerdict string       `json:"from_verdict"`
	ToVerdict   string       `json:"to_verdict"`
	FromStatus  model.Status `json:"from_status"`
	ToStatus    model.Status `json:"to_status"`
	Changes     []ChangeItem `json:"changes"`
}

// ErrNotFound : entrée d'historique introuvable.
var ErrNotFound = errors.New("not found")

// Diff compare deux entrées d'historique, la plus ancienne en premier.
func Diff(s *history.Store, idA, idB string, l i18n.Lang) (*DiffResult, error) {
	if s == nil {
		return nil, ErrNotFound
	}
	a, err1 := s.Load(idA)
	b, err2 := s.Load(idB)
	if err1 != nil || err2 != nil {
		return nil, ErrNotFound
	}
	if a.Time.After(b.Time) {
		a, b = b, a
	}
	d := &DiffResult{From: a.ID, To: b.ID, FromRaw: a.Raw, ToRaw: b.Raw,
		FromTime: a.Time.Format("2006-01-02T15:04:05Z07:00"), ToTime: b.Time.Format("2006-01-02T15:04:05Z07:00"),
		SameTarget: a.TargetKey == b.TargetKey, SameNetwork: a.Network == b.Network,
		FromVerdict: a.Report.Verdict.Headline.In(l), ToVerdict: b.Report.Verdict.Headline.In(l),
		FromStatus: a.Report.Verdict.Status, ToStatus: b.Report.Verdict.Status,
		Changes: []ChangeItem{}}
	for _, c := range history.Compare(a.Report, b.Report) {
		d.Changes = append(d.Changes, ChangeItem{c, c.Msg.In(l)})
	}
	return d, nil
}

// Catalog renvoie toutes les traductions dans la langue l.
func Catalog(l i18n.Lang) map[string]string {
	out := map[string]string{}
	for _, k := range i18n.Keys() {
		out[k] = i18n.T(l, k)
	}
	return out
}
