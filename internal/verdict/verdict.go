// Package verdict croise les résultats des sondes pour produire un
// diagnostic en langage support. Chaque règle est déclarée dans le code et
// testée individuellement.
package verdict

import (
	"slices"
	"strconv"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

// Facts regroupe ce que les règles consultent.
type Facts struct {
	Run *model.Report
	T   *model.TargetReport
}

func (f Facts) env() *model.EnvResult { return f.Run.Env }

func (f Facts) tcp(fam string) *model.TCPResult { return f.T.TCPFamily(fam) }

// anyConnected : une famille au moins a connecté.
func (f Facts) anyConnected() bool {
	for _, t := range f.T.TCP {
		if t.Outcome == "connected" {
			return true
		}
	}
	return false
}

// outcomes renvoie les issues TCP des familles réellement testées.
func (f Facts) outcomes() []string {
	var o []string
	for _, t := range f.T.TCP {
		switch t.Outcome {
		case "", "no_address", "no_local", "excluded":
		default:
			o = append(o, t.Outcome)
		}
	}
	return o
}

func (f Facts) allOutcomes(want string) bool {
	o := f.outcomes()
	if len(o) == 0 {
		return false
	}
	for _, x := range o {
		if x != want {
			return false
		}
	}
	return true
}

// bestTrace renvoie le traceroute disponible le plus informatif.
func (f Facts) bestTrace() *model.TraceResult {
	var best *model.TraceResult
	for _, t := range f.T.Traces {
		if t == nil || !t.Available {
			continue
		}
		if best == nil || (t.Reached && !best.Reached) || (t.Reached == best.Reached && t.LastHop > best.LastHop) {
			best = t
		}
	}
	return best
}

func (f Facts) port() string { return strconv.Itoa(f.T.Target.Port) }

// Rule est une règle de diagnostic.
type Rule struct {
	ID       string
	Severity model.Status
	Layer    string
	Match    func(Facts) (msg, advice i18n.Msg, ok bool)
}

// groups : au sein d'un groupe, seule la première règle qui correspond est
// retenue (causes mutuellement exclusives).
var groups = map[string]string{
	"dns_nx": "dns", "dns_all_fail": "dns", "dns_sinkhole": "dns", "dns_local_nx": "dns",
	"dns_local_fail": "dns", "dns_differs": "dns",
	"tcp_refused": "tcp", "smtp25_blocked": "tcp", "tcp_timeout_local": "tcp", "tcp_timeout_remote_path": "tcp",
	"tcp_filtered_at_server": "tcp", "tcp_timeout": "tcp", "tcp_unreachable": "tcp", "tcp_failed": "tcp",
	"tls_handshake": "tls_chain", "tls_intercepted_untrusted": "tls_chain", "tls_selfsigned": "tls_chain",
	"tls_missing_intermediate": "tls_chain", "tls_untrusted": "tls_chain",
	"http_proxy_auth": "http", "http_server_error": "http", "http_no_answer": "http",
	"http_forbidden": "http", "http_client_error": "http",
}

func m(k string, a ...any) i18n.Msg { return i18n.M(k, a...) }

// Rules : l'ordre définit la priorité à gravité égale (la cause la plus en
// amont d'abord).
var Rules = []Rule{
	{"no_network", model.Fail, "env", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		e := f.env()
		return m("v.no_network"), m("a.no_network"), e != nil && e.LocalIPv4 == "" && e.LocalIPv6 == ""
	}},
	{"gateway_down", model.Fail, "env", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		e := f.env()
		ok := e != nil && e.GatewayPing != nil && e.GatewayPing.Error == "" && e.GatewayPing.Sent > 0 &&
			e.GatewayPing.Recv == 0 && !f.anyConnected() && (f.T.DNS == nil || f.T.DNS.Status == model.Fail)
		if ok {
			return m("v.gateway_down", e.GatewayPing.Target), m("a.gateway_down"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"captive_portal", model.Fail, "captive", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		c := f.Run.Captive
		return m("v.captive"), m("a.captive"), c != nil && c.Captive == "probable"
	}},
	{"dns_nx", model.Fail, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		d := f.T.DNS
		if d != nil && d.Verdict == "nx" {
			return m("v.dns_nx", d.Name), m("a.dns_nx"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"dns_all_fail", model.Fail, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		d := f.T.DNS
		if d != nil && (d.Verdict == "all_fail" || d.Verdict == "noaddr") {
			return m("v.dns_all_fail", d.Name), m("a.dns_all_fail"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"dns_sinkhole", model.Fail, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		d := f.T.DNS
		if d != nil && d.Verdict == "sinkhole" {
			return m("v.dns_sinkhole", d.Name), m("a.dns_filter"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"dns_local_nx", model.Fail, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		d := f.T.DNS
		if d != nil && d.Verdict == "local_nx" {
			return m("v.dns_local_nx", d.Name), m("a.dns_filter"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"dns_local_fail", model.Fail, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		d := f.T.DNS
		if d != nil && d.Verdict == "local_fail" {
			return m("v.dns_local_fail"), m("a.dns_local_fail"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"dns_differs", model.Warn, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		d := f.T.DNS
		if d != nil && d.Verdict == "differs" {
			return m("v.dns_differs"), m("a.dns_differs"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"tcp_refused", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		return m("v.tcp_refused", f.port()), m("a.tcp_refused"), f.allOutcomes("refused")
	}},
	{"smtp25_blocked", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		ok := f.T.Target.Port == 25 && f.allOutcomes("timeout")
		return m("v.smtp25_blocked"), m("a.smtp25_blocked"), ok
	}},
	{"tcp_timeout_local", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		tr := f.bestTrace()
		ok := f.allOutcomes("timeout") && tr != nil && !tr.Reached && tr.LastHop <= 2
		if ok {
			return m("v.tcp_timeout_local", f.port(), tr.LastHop), m("a.tcp_timeout_local"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"tcp_timeout_remote_path", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		tr := f.bestTrace()
		ok := f.allOutcomes("timeout") && tr != nil && !tr.Reached && tr.LastHop > 2
		if ok {
			return m("v.tcp_timeout_path", f.port(), tr.LastHop), m("a.tcp_timeout_path"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"tcp_filtered_at_server", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		tr := f.bestTrace()
		ok := f.allOutcomes("timeout") && tr != nil && tr.Reached
		return m("v.tcp_filtered_server", f.port()), m("a.tcp_filtered_server"), ok
	}},
	{"tcp_timeout", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		ok := f.allOutcomes("timeout") && f.bestTrace() == nil
		return m("v.tcp_timeout", f.port()), m("a.tcp_timeout"), ok
	}},
	{"tcp_unreachable", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		return m("v.tcp_unreachable"), m("a.tcp_unreachable"), f.allOutcomes("unreachable")
	}},
	{"tcp_failed", model.Fail, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		ok := len(f.outcomes()) > 0 && !f.anyConnected()
		return m("v.tcp_failed", f.port()), m("a.tcp_timeout"), ok
	}},
	{"ipv6_broken", model.Warn, "tcp", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		v4, v6 := f.tcp("ipv4"), f.tcp("ipv6")
		ok := v4 != nil && v6 != nil && v4.Outcome == "connected" && slices.Contains([]string{"timeout", "unreachable", "refused", "error"}, v6.Outcome)
		return m("v.ipv6_broken"), m("a.ipv6_broken"), ok
	}},
	{"tls_handshake", model.Fail, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		if t != nil && t.Error != "" && f.anyConnected() {
			return m("v.tls_handshake", t.Error), m("a.tls_handshake"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"tls_expired", model.Fail, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		return m("v.tls_expired"), m("a.tls_server_cert"), t != nil && t.Expired
	}},
	{"tls_hostname", model.Fail, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		ok := t != nil && t.Error == "" && len(t.Chain) > 0 && !t.HostnameOK && !(t.SelfSigned && f.T.Target.Proto == "rdp")
		return m("v.tls_hostname", f.T.Target.Host), m("a.tls_server_cert"), ok
	}},
	{"tls_intercepted_untrusted", model.Fail, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		if t != nil && t.Intercepted && !t.SystemOK {
			return m("v.tls_intercepted_untrusted", t.InterceptIssuer), m("a.tls_intercepted_untrusted"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"tls_selfsigned", model.Fail, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		ok := t != nil && t.SelfSigned && f.T.Target.Proto != "rdp"
		return m("v.tls_selfsigned"), m("a.tls_server_cert"), ok
	}},
	{"tls_missing_intermediate", model.Warn, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		return m("v.tls_missing_intermediate"), m("a.tls_missing_intermediate"), t != nil && t.MissingIntermediate
	}},
	{"tls_untrusted", model.Fail, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		ok := t != nil && t.Error == "" && len(t.Chain) > 0 && !t.SystemOK && !t.MozillaOK &&
			!t.SelfSigned && !t.Expired && !t.Intercepted && !t.MissingIntermediate
		return m("v.tls_untrusted"), m("a.tls_server_cert"), ok
	}},
	{"http_proxy_auth", model.Warn, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		h := f.T.HTTP
		return m("v.http_proxy_auth"), m("a.http_proxy_auth"), h != nil && h.Code == 407
	}},
	{"http_server_error", model.Fail, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		h := f.T.HTTP
		if h != nil && h.Code >= 500 {
			return m("v.http_server_error", h.Code), m("a.http_server_error"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"http_no_answer", model.Fail, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		h := f.T.HTTP
		ok := h != nil && h.Code == 0 && h.Error != "" && f.anyConnected() && (f.T.TLS == nil || f.T.TLS.Error == "")
		if ok {
			return m("v.http_no_answer", h.ErrorKind), m("a.http_no_answer"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"http_forbidden", model.Warn, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		h := f.T.HTTP
		if h != nil && (h.Code == 403 || h.Code == 451) {
			return m("v.http_forbidden", h.Code), m("a.http_forbidden"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"http_client_error", model.Warn, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		h := f.T.HTTP
		if h != nil && h.Code >= 400 && h.Code < 500 && h.Code != 401 && h.Code != 403 && h.Code != 407 && h.Code != 451 {
			return m("v.http_client_error", h.Code), m("a.http_client_error"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"proto_failed", model.Fail, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		p := f.T.Proto
		if p != nil && p.Status == model.Fail && f.anyConnected() {
			return m("v.proto_failed", upper(p.Proto)), m("a.proto_failed"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"tls_intercepted", model.Warn, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		if t != nil && t.Intercepted && t.SystemOK {
			v := t.InterceptVendor
			if v == "" {
				v = t.InterceptIssuer
			}
			return m("v.tls_intercepted", v), m("a.tls_intercepted"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"h3_blocked", model.Warn, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		h := f.T.HTTP3
		ok := h != nil && h.Advertised && h.Attempted && !h.OK
		return m("v.h3_blocked"), m("a.h3_blocked"), ok
	}},
	{"rdp_no_nla", model.Warn, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		p := f.T.Proto
		ok := p != nil && p.RDP != nil && p.RDP.Failure == "" && !p.RDP.NLARequired
		return m("v.rdp_no_nla"), m("a.rdp_no_nla"), ok
	}},
	{"proto_no_tls", model.Warn, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		p := f.T.Proto
		ok := p != nil && slices.Contains([]string{"smtp", "imap", "pop3", "ftp", "ldap"}, p.Proto) &&
			(p.TLSMode == "none" || p.TLSMode == "refused") && p.Status != model.Fail
		if ok {
			return m("v.proto_no_tls", upper(p.Proto)), m("a.proto_no_tls"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"ssh_obsolete", model.Warn, "app", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		p := f.T.Proto
		ok := p != nil && p.SSH != nil && len(p.SSH.Obsolete) > 0
		return m("v.ssh_obsolete"), m("a.ssh_obsolete"), ok
	}},
	{"tls_expiring", model.Warn, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		if t != nil && len(t.Chain) > 0 && !t.Expired && t.DaysLeft < 30 {
			return m("v.tls_expiring", t.DaysLeft), m("a.tls_server_cert"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"tls_weak", model.Warn, "tls", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		t := f.T.TLS
		return m("v.tls_weak"), m("a.tls_weak"), t != nil && len(t.Weak) > 0
	}},
	{"dns_interception", model.Warn, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		g := f.Run.DNSGlobal
		return m("v.dns_interception"), m("a.dns_interception"), g != nil && g.Intercepted
	}},
	{"nxdomain_hijack", model.Info, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		g := f.Run.DNSGlobal
		return m("v.nxdomain_hijack"), m("a.nxdomain_hijack"), g != nil && g.NXHijack
	}},
	{"transparent_proxy", model.Warn, "proxy", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		p, c := f.T.Proxy, f.Run.Captive
		ok := (p != nil && p.Suspicion == "probable") || (c != nil && c.TransparentProxy == "probable")
		return m("v.transparent_proxy"), m("a.transparent_proxy"), ok
	}},
	{"path_loss", model.Warn, "trace", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		tr := f.bestTrace()
		if tr != nil && tr.Reached && tr.LossFrom > 0 {
			return m("v.path_loss", tr.LossFrom), m("a.path_loss"), true
		}
		return i18n.Msg{}, i18n.Msg{}, false
	}},
	{"path_loop", model.Warn, "trace", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		tr := f.bestTrace()
		return m("v.path_loop"), m("a.path_loop"), tr != nil && tr.Loop
	}},
	{"dns_fallback", model.Info, "dns", func(f Facts) (i18n.Msg, i18n.Msg, bool) {
		d := f.T.DNS
		return m("v.dns_fallback"), i18n.Msg{}, d != nil && d.Fallback
	}},
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

// Evaluate applique toutes les règles à une cible.
func Evaluate(run *model.Report, t *model.TargetReport) model.Verdict {
	f := Facts{Run: run, T: t}
	if run == nil {
		f.Run = &model.Report{}
	}
	var v model.Verdict
	done := map[string]bool{}
	for _, r := range Rules {
		g := groups[r.ID]
		if g != "" && done[g] {
			continue
		}
		msg, adv, ok := r.Match(f)
		if !ok {
			continue
		}
		if g != "" {
			done[g] = true
		}
		v.Findings = append(v.Findings, model.Finding{Rule: r.ID, Severity: r.Severity, Layer: r.Layer, Msg: msg, Advice: adv})
	}
	// Tri stable par gravité (l'ordre des règles départage).
	slices.SortStableFunc(v.Findings, func(a, b model.Finding) int { return b.Severity.Rank() - a.Severity.Rank() })
	switch {
	case t.Error != "":
		v.Status = model.Fail
		v.Headline = m("v.target_error", t.Error)
	case len(v.Findings) == 0 || v.Findings[0].Severity == model.Info:
		v.Status = model.OK
		v.Headline = m("v.all_ok", upper(t.Target.Proto))
	default:
		v.Status = v.Findings[0].Severity
		v.Headline = v.Findings[0].Msg
	}
	return v
}
