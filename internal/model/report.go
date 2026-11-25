package model

import (
	"strconv"
	"time"

	"github.com/maxb1906/jalon/internal/config"
	"github.com/maxb1906/jalon/internal/i18n"
)

// Target est une cible analysée.
type Target struct {
	Raw         string `json:"raw"`
	Scheme      string `json:"scheme"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Path        string `json:"path,omitempty"`
	Proto       string `json:"proto"` // http, https, smtp, imap, pop3, ssh, rdp, ldap, ftp, banner
	ImplicitTLS bool   `json:"implicit_tls"`
	IsIP        bool   `json:"is_ip"`
}

// Key est la clé d'historique de la cible.
func (t Target) Key() string {
	return t.Proto + "://" + t.Host + ":" + strconv.Itoa(t.Port) + t.Path
}

// Display renvoie une forme lisible.
func (t Target) Display() string { return t.Raw }

// Finding est une conclusion d'une règle de verdict.
type Finding struct {
	Rule     string   `json:"rule"`
	Severity Status   `json:"severity"`
	Layer    string   `json:"layer"`
	Msg      i18n.Msg `json:"msg"`
	Advice   i18n.Msg `json:"advice,omitzero"`
}

// Verdict est la synthèse d'une cible.
type Verdict struct {
	Status   Status    `json:"status"`
	Headline i18n.Msg  `json:"headline"`
	Findings []Finding `json:"findings,omitempty"`
}

// Change est une différence avec le diagnostic précédent.
type Change struct {
	Kind     string   `json:"kind"` // ips, cert, path, latency, layer
	Severity Status   `json:"severity"`
	Msg      i18n.Msg `json:"msg"`
}

// Comparison décrit la comparaison avec un diagnostic antérieur.
type Comparison struct {
	PreviousID   string    `json:"previous_id"`
	PreviousTime time.Time `json:"previous_time"`
	SameNetwork  bool      `json:"same_network"`
	Changes      []Change  `json:"changes,omitempty"`
}

// TargetReport rassemble tous les résultats d'une cible.
type TargetReport struct {
	Target    Target         `json:"target"`
	Started   time.Time      `json:"started"`
	Finished  time.Time      `json:"finished"`
	Error     string         `json:"error,omitempty"`
	DNS       *DNSResult     `json:"dns,omitempty"`
	TCP       []*TCPResult   `json:"tcp,omitempty"`
	TLS       *TLSResult     `json:"tls,omitempty"`
	HTTP      *HTTPResult    `json:"http,omitempty"`
	HTTP3     *HTTP3Result   `json:"http3,omitempty"`
	Proto     *ProtoResult   `json:"proto,omitempty"`
	Traces    []*TraceResult `json:"traces,omitempty"`
	Proxy     *ProxyResult   `json:"proxy,omitempty"`
	ChosenIP  string         `json:"chosen_ip,omitempty"`
	Verdict   Verdict        `json:"verdict"`
	Compare   *Comparison    `json:"compare,omitempty"`
	HistoryID string         `json:"history_id,omitempty"`
}

// TCPFamily renvoie le résultat TCP de la famille demandée.
func (r *TargetReport) TCPFamily(f string) *TCPResult {
	for _, t := range r.TCP {
		if t.Family == f {
			return t
		}
	}
	return nil
}

// Trace renvoie le traceroute du mode demandé.
func (r *TargetReport) Trace(mode string) *TraceResult {
	for _, t := range r.Traces {
		if t.Mode == mode {
			return t
		}
	}
	return nil
}

// Steps renvoie la vue ordonnée des étapes exécutées.
func (r *TargetReport) Steps() []Step {
	var s []Step
	if r.DNS != nil {
		s = append(s, Step{ID: "dns", Layer: "layer.dns", Base: &r.DNS.Base})
	}
	for _, t := range r.TCP {
		s = append(s, Step{ID: "tcp_" + t.Family, Layer: "layer.tcp_" + t.Family, Base: &t.Base})
	}
	if r.TLS != nil {
		s = append(s, Step{ID: "tls", Layer: "layer.tls", Base: &r.TLS.Base})
	}
	if r.HTTP != nil {
		s = append(s, Step{ID: "http", Layer: "layer.http", Base: &r.HTTP.Base})
	}
	if r.HTTP3 != nil {
		s = append(s, Step{ID: "http3", Layer: "layer.http3", Base: &r.HTTP3.Base})
	}
	if r.Proto != nil {
		s = append(s, Step{ID: "proto", Layer: "layer.proto." + r.Proto.Proto, Base: &r.Proto.Base})
	}
	if r.Proxy != nil {
		s = append(s, Step{ID: "proxy", Layer: "layer.proxy", Base: &r.Proxy.Base})
	}
	for _, t := range r.Traces {
		s = append(s, Step{ID: "trace_" + t.Mode, Layer: "layer.trace_" + t.Mode, Base: &t.Base})
	}
	return s
}

// LayerStatus renvoie un statut synthétique par couche pour le tableau
// multi-cible : dns, tcp, tls, app, trace.
func (r *TargetReport) LayerStatus() map[string]Status {
	m := map[string]Status{"dns": Skipped, "tcp": Skipped, "tls": Skipped, "app": Skipped, "trace": Skipped}
	if r.DNS != nil {
		m["dns"] = r.DNS.Status
	}
	// TCP : le meilleur des deux familles (une famille OK suffit), mais un
	// avertissement si l'autre est cassée.
	var tcp []Status
	best := Skipped
	for _, t := range r.TCP {
		tcp = append(tcp, t.Status)
		if t.Status == OK {
			best = OK
		}
	}
	if best == OK {
		w := Worst(tcp...)
		if w == Fail || w == Warn {
			m["tcp"] = Warn
		} else {
			m["tcp"] = OK
		}
	} else if len(tcp) > 0 {
		m["tcp"] = Worst(tcp...)
	}
	if r.TLS != nil {
		m["tls"] = r.TLS.Status
	}
	switch {
	case r.HTTP != nil:
		app := r.HTTP.Status
		if r.HTTP3 != nil && r.HTTP3.Status == Warn && app == OK {
			app = Warn
		}
		m["app"] = app
	case r.Proto != nil:
		m["app"] = r.Proto.Status
	}
	var tr []Status
	for _, t := range r.Traces {
		tr = append(tr, t.Status)
	}
	if len(tr) > 0 {
		m["trace"] = Worst(tr...)
	}
	return m
}

// Report est le rapport complet d'une exécution.
type Report struct {
	Tool      string          `json:"tool"`
	Version   string          `json:"version"`
	Lang      i18n.Lang       `json:"lang"`
	Started   time.Time       `json:"started"`
	Finished  time.Time       `json:"finished"`
	Env       *EnvResult      `json:"env,omitempty"`
	DNSGlobal *DNSGlobal      `json:"dns_global,omitempty"`
	Captive   *CaptiveResult  `json:"captive,omitempty"`
	Targets   []*TargetReport `json:"targets"`
	Status    Status          `json:"status"`
	ExitCode  int             `json:"exit_code"`

	// Page de garde des rapports (config.yaml) : technicien et émetteur.
	Technician string         `json:"technician,omitempty"`
	Issuer     *config.Issuer `json:"issuer,omitempty"`

	// LogoDataURI est le logo de l'émetteur en data: URI (rapport HTML seulement).
	LogoDataURI string `json:"-"`
}

// GlobalSteps renvoie les étapes communes à toutes les cibles.
func (r *Report) GlobalSteps() []Step {
	var s []Step
	if r.Env != nil {
		s = append(s, Step{ID: "env", Layer: "layer.env", Base: &r.Env.Base})
	}
	if r.DNSGlobal != nil {
		s = append(s, Step{ID: "dns_global", Layer: "layer.dns_global", Base: &r.DNSGlobal.Base})
	}
	if r.Captive != nil {
		s = append(s, Step{ID: "captive", Layer: "layer.captive", Base: &r.Captive.Base})
	}
	return s
}

// ComputeExit calcule le statut global et le code de sortie
// (0 OK, 1 avertissement, 2 échec).
func (r *Report) ComputeExit() {
	var ss []Status
	for _, t := range r.Targets {
		ss = append(ss, t.Verdict.Status)
	}
	r.Status = Worst(ss...)
	switch r.Status {
	case Fail:
		r.ExitCode = 2
	case Warn:
		r.ExitCode = 1
	default:
		r.ExitCode = 0
		if r.Status == Skipped {
			r.Status = OK
		}
	}
}
