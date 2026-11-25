package report

import (
	"html/template"
	"io"
	"strings"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

// HTML écrit un rapport HTML autonome (aucune ressource externe).
func HTML(w io.Writer, rep *model.Report) error {
	l := rep.Lang
	funcs := template.FuncMap{
		"t":      func(k string, a ...any) string { return i18n.T(l, k, a...) },
		"msg":    func(m i18n.Msg) string { return m.In(l) },
		"icon":   Icon,
		"st":     func(s model.Status) string { return StatusText(l, s) },
		"short":  func(s model.Status) string { return shortStatus(l, s) },
		"cls":    func(s model.Status) string { return "s-" + string(orSkipped(s)) },
		"time":   fmtTime,
		"ticket": func(t *model.TargetReport) string { return Ticket(rep, t) },
		"cols":   func() []string { return Columns },
		"layer":  func(t *model.TargetReport, c string) model.Status { return t.LayerStatus()[c] },
		"join":   strings.Join,
		"first":  func(s ...string) string { return firstNon(append(s, "-")...) },
		"upper":  strings.ToUpper,
		"hopname": func(h model.Hop) string {
			if h.Addr == "" {
				return "*"
			}
			if h.Name != "" {
				return h.Name + " (" + h.Addr + ")"
			}
			return h.Addr
		},
		"advice": func(v model.Verdict) string {
			if len(v.Findings) > 0 && v.Status != model.OK && !v.Findings[0].Advice.IsZero() {
				return v.Findings[0].Advice.In(l)
			}
			return ""
		},
		"others": func(v model.Verdict) []model.Finding {
			if v.Status != model.OK && len(v.Findings) > 0 {
				return v.Findings[1:]
			}
			return v.Findings
		},
	}
	tpl, err := template.New("r").Funcs(funcs).Parse(htmlTpl)
	if err != nil {
		return err
	}
	return tpl.Execute(w, rep)
}

func orSkipped(s model.Status) model.Status {
	if s == "" {
		return model.Skipped
	}
	return s
}

// CSS commun au rapport HTML et à l'UI web.
const CSS = `
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#5f6b7a;--line:#e2e6eb;--ok:#1a7f37;--warn:#9a6700;--fail:#cf222e;--info:#0969da;--skip:#8c959f}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b22;--fg:#e6edf3;--mut:#8b96a5;--line:#2a313c;--ok:#3fb950;--warn:#d29922;--fail:#f85149;--info:#58a6ff;--skip:#6e7681}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:0 0 10px}h3{font-size:14px;margin:16px 0 6px;color:var(--mut)}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:16px 0}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
.s-ok{color:var(--ok)}.s-warn{color:var(--warn)}.s-fail{color:var(--fail)}.s-info{color:var(--info)}.s-skipped{color:var(--skip)}
.verdict{font-size:16px;font-weight:600;padding:10px 12px;border-radius:8px;border-left:4px solid currentColor;background:color-mix(in srgb,currentColor 8%,transparent)}
.advice{margin:8px 0 0;color:var(--fg)}.note{font-size:13px;color:var(--mut)}.note .ic{margin-right:4px}
.ic{display:inline-block;width:1.2em;text-align:center}.layer{white-space:nowrap;font-weight:500}
pre{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;white-space:pre-wrap;font:12px/1.45 ui-monospace,Menlo,Consolas,monospace}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
`

const htmlTpl = `<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{t "html.title"}} — {{time .Started}}</title><style>` + CSS + `</style></head><body><main>
<h1>{{t "html.title"}}</h1>
<div class="mut">{{t "html.generated" .Version (time .Started)}}</div>
{{with .Env}}<div class="mut">{{t "text.host" .Hostname .OS (first .LocalIPv4 .LocalIPv6) (first (join .Gateways ", ")) (first .PublicIP)}}</div>{{end}}
{{if gt (len .Targets) 1}}<div class="card"><h2>{{t "text.synthesis"}}</h2><table><tr><th>{{t "col.target"}}</th>{{range cols}}<th>{{t (print "col." .)}}</th>{{end}}<th>{{t "col.verdict"}}</th></tr>
{{range .Targets}}{{if .}}{{$tr := .}}<tr><td>{{.Target.Raw}}</td>{{range cols}}{{$s := layer $tr .}}<td class="{{cls $s}}">{{icon $s}} {{short $s}}</td>{{end}}<td class="{{cls .Verdict.Status}}">{{msg .Verdict.Headline}}</td></tr>{{end}}{{end}}
</table></div>{{end}}
{{with .GlobalSteps}}<div class="card"><h2>{{t "text.common"}}</h2>{{template "steps" .}}</div>{{end}}
{{range .Targets}}{{if .}}<div class="card">
<h2>{{.Target.Raw}} <span class="mut">({{upper .Target.Proto}}, {{.Target.Host}}:{{.Target.Port}})</span></h2>
<div class="verdict {{cls .Verdict.Status}}">{{icon .Verdict.Status}} {{msg .Verdict.Headline}}{{with advice .Verdict}}<div class="advice">→ {{.}}</div>{{end}}</div>
{{with others .Verdict}}<ul>{{range .}}<li class="{{cls .Severity}}">{{icon .Severity}} {{msg .Msg}}</li>{{end}}</ul>{{end}}
{{template "steps" .Steps}}
{{range .Traces}}{{if and .Available .Hops}}<h3>{{t (print "layer.trace_" .Mode)}}</h3>
<table><tr><th>#</th><th>{{t "hop.host"}}</th><th class="num">{{t "hop.loss"}}</th><th class="num">min</th><th class="num">{{t "hop.avg"}}</th><th class="num">max</th><th class="num">{{t "hop.jitter"}}</th></tr>
{{range .Hops}}<tr><td>{{.TTL}}</td><td>{{hopname .}}{{if .ASN}} <span class="mut">{{.ASN}}</span>{{end}}</td><td class="num">{{printf "%.0f" .LossPct}} %</td>{{if .Recv}}<td class="num">{{printf "%.1f" .MinMs}}</td><td class="num">{{printf "%.1f" .AvgMs}}</td><td class="num">{{printf "%.1f" .MaxMs}}</td><td class="num">{{printf "%.1f" .JitterMs}}</td>{{else}}<td class="num">-</td><td class="num">-</td><td class="num">-</td><td class="num">-</td>{{end}}</tr>{{end}}
</table>{{end}}{{end}}
{{with .Compare}}<h3>{{t "text.changes" (time .PreviousTime)}}{{if not .SameNetwork}} {{t "text.other_network"}}{{end}}</h3>
{{if .Changes}}<ul>{{range .Changes}}<li class="{{cls .Severity}}">{{icon .Severity}} {{msg .Msg}}</li>{{end}}</ul>{{else}}<p class="mut">{{t "text.no_changes"}}</p>{{end}}{{end}}
<h3>{{t "text.ticket"}}</h3><pre>{{ticket .}}</pre>
</div>{{end}}{{end}}
<p class="mut">Jalon — GPL-3.0 — https://github.com/maxb1906/jalon</p>
</main></body></html>
{{define "steps"}}<table><tr><th></th><th>{{t "html.layer"}}</th><th>{{t "html.result"}}</th><th class="num">ms</th></tr>
{{range .}}<tr><td class="{{cls .Status}}"><span class="ic">{{icon .Status}}</span></td><td class="layer">{{t .Layer}}</td><td><div class="{{cls .Status}}">{{msg .Summary}}</div>
{{range .Notes}}<div class="note"><span class="ic {{cls .Status}}">{{icon .Status}}</span>{{msg .Msg}}</div>{{end}}</td><td class="num mut">{{printf "%.0f" .DurationMs}}</td></tr>{{end}}</table>{{end}}`
