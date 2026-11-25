package verdict

import (
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/model"
)

// base renvoie un diagnostic HTTPS entièrement OK.
func base() (*model.Report, *model.TargetReport) {
	run := &model.Report{
		Env:       &model.EnvResult{LocalIPv4: "10.0.0.2", Gateways: []string{"10.0.0.1"}, GatewayPing: &model.PingStat{Target: "10.0.0.1", Sent: 3, Recv: 3}},
		DNSGlobal: &model.DNSGlobal{},
		Captive:   &model.CaptiveResult{Captive: "no", TransparentProxy: "no"},
	}
	ok := model.Base{Status: model.OK}
	t := &model.TargetReport{
		Target: model.Target{Raw: "https://site.test", Host: "site.test", Port: 443, Proto: "https"},
		DNS:    &model.DNSResult{Base: ok, Name: "site.test", Verdict: "same", IPv4: []string{"192.0.2.1"}},
		TCP: []*model.TCPResult{
			{Base: ok, Family: "ipv4", Outcome: "connected", IP: "192.0.2.1"},
			{Base: model.Base{Status: model.Skipped}, Family: "ipv6", Outcome: "no_address"},
		},
		TLS:    &model.TLSResult{Base: ok, SystemOK: true, MozillaOK: true, HostnameOK: true, DaysLeft: 200, Chain: []model.CertInfo{{Subject: "site.test"}}},
		HTTP:   &model.HTTPResult{Base: ok, Code: 200},
		HTTP3:  &model.HTTP3Result{Base: model.Base{Status: model.Skipped}},
		Proxy:  &model.ProxyResult{Base: ok, Suspicion: "no"},
		Traces: []*model.TraceResult{{Base: ok, Mode: "icmp", Available: true, Reached: true, LastHop: 8}},
	}
	return run, t
}

func timeoutTCP(t *model.TargetReport) {
	t.TCP[0].Outcome, t.TCP[0].Status = "timeout", model.Fail
	t.TLS, t.HTTP, t.HTTP3 = nil, nil, nil
}

func protoTarget(t *model.TargetReport, proto string, port int) {
	t.Target.Proto, t.Target.Port = proto, port
	t.HTTP, t.HTTP3, t.TLS = nil, nil, nil
	t.Proto = &model.ProtoResult{Base: model.Base{Status: model.OK}, Proto: proto, TLSMode: "starttls"}
}

// cases : règle attendue en tête (ou présente) → mutation.
var cases = map[string]func(*model.Report, *model.TargetReport){
	"no_network": func(r *model.Report, t *model.TargetReport) { r.Env.LocalIPv4 = "" },
	"gateway_down": func(r *model.Report, t *model.TargetReport) {
		r.Env.GatewayPing.Recv = 0
		t.DNS.Status, t.DNS.Verdict = model.Fail, "all_fail"
		timeoutTCP(t)
	},
	"captive_portal": func(r *model.Report, t *model.TargetReport) { r.Captive.Captive = "probable" },
	"dns_nx":         func(r *model.Report, t *model.TargetReport) { t.DNS.Verdict = "nx" },
	"dns_all_fail":   func(r *model.Report, t *model.TargetReport) { t.DNS.Verdict = "all_fail" },
	"dns_sinkhole":   func(r *model.Report, t *model.TargetReport) { t.DNS.Verdict = "sinkhole" },
	"dns_local_nx":   func(r *model.Report, t *model.TargetReport) { t.DNS.Verdict = "local_nx" },
	"dns_local_fail": func(r *model.Report, t *model.TargetReport) { t.DNS.Verdict = "local_fail" },
	"dns_differs":    func(r *model.Report, t *model.TargetReport) { t.DNS.Verdict = "differs" },
	"tcp_refused": func(r *model.Report, t *model.TargetReport) {
		t.TCP[0].Outcome = "refused"
		t.TLS, t.HTTP = nil, nil
	},
	"smtp25_blocked": func(r *model.Report, t *model.TargetReport) {
		timeoutTCP(t)
		t.Target.Port, t.Target.Proto = 25, "smtp"
		t.Traces = nil
	},
	"tcp_timeout_local": func(r *model.Report, t *model.TargetReport) {
		timeoutTCP(t)
		t.Traces[0].Reached, t.Traces[0].LastHop = false, 1
	},
	"tcp_timeout_remote_path": func(r *model.Report, t *model.TargetReport) {
		timeoutTCP(t)
		t.Traces[0].Reached, t.Traces[0].LastHop = false, 6
	},
	"tcp_filtered_at_server": func(r *model.Report, t *model.TargetReport) { timeoutTCP(t) },
	"tcp_timeout": func(r *model.Report, t *model.TargetReport) {
		timeoutTCP(t)
		t.Traces = nil
	},
	"tcp_unreachable": func(r *model.Report, t *model.TargetReport) {
		t.TCP[0].Outcome = "unreachable"
		t.TLS, t.HTTP = nil, nil
	},
	"tcp_failed": func(r *model.Report, t *model.TargetReport) {
		t.TCP[0].Outcome = "timeout"
		t.TCP[1].Outcome = "refused"
		t.TLS, t.HTTP = nil, nil
	},
	"ipv6_broken": func(r *model.Report, t *model.TargetReport) { t.TCP[1].Outcome = "timeout" },
	"tls_handshake": func(r *model.Report, t *model.TargetReport) {
		t.TLS = &model.TLSResult{Base: model.Base{Status: model.Fail}, Error: "connection reset"}
	},
	"tls_expired":  func(r *model.Report, t *model.TargetReport) { t.TLS.Expired = true },
	"tls_hostname": func(r *model.Report, t *model.TargetReport) { t.TLS.HostnameOK = false },
	"tls_intercepted_untrusted": func(r *model.Report, t *model.TargetReport) {
		t.TLS.Intercepted, t.TLS.SystemOK, t.TLS.MozillaOK, t.TLS.InterceptIssuer = true, false, false, "Fortinet CA"
	},
	"tls_selfsigned":           func(r *model.Report, t *model.TargetReport) { t.TLS.SelfSigned = true },
	"tls_missing_intermediate": func(r *model.Report, t *model.TargetReport) { t.TLS.MissingIntermediate, t.TLS.MozillaOK = true, false },
	"tls_untrusted":            func(r *model.Report, t *model.TargetReport) { t.TLS.SystemOK, t.TLS.MozillaOK = false, false },
	"http_proxy_auth":          func(r *model.Report, t *model.TargetReport) { t.HTTP.Code = 407 },
	"http_server_error":        func(r *model.Report, t *model.TargetReport) { t.HTTP.Code = 502 },
	"http_no_answer": func(r *model.Report, t *model.TargetReport) {
		t.HTTP.Code, t.HTTP.Error, t.HTTP.ErrorKind = 0, "timeout", "timeout"
	},
	"http_forbidden":    func(r *model.Report, t *model.TargetReport) { t.HTTP.Code = 403 },
	"http_client_error": func(r *model.Report, t *model.TargetReport) { t.HTTP.Code = 404 },
	"proto_failed": func(r *model.Report, t *model.TargetReport) {
		protoTarget(t, "imap", 143)
		t.Proto.Status = model.Fail
	},
	"tls_intercepted": func(r *model.Report, t *model.TargetReport) {
		t.TLS.Intercepted, t.TLS.MozillaOK, t.TLS.InterceptVendor = true, false, "Zscaler"
	},
	"h3_blocked": func(r *model.Report, t *model.TargetReport) {
		t.HTTP3 = &model.HTTP3Result{Base: model.Base{Status: model.Warn}, Advertised: true, Attempted: true}
	},
	"rdp_no_nla": func(r *model.Report, t *model.TargetReport) {
		protoTarget(t, "rdp", 3389)
		t.Proto.RDP = &model.RDPInfo{Selected: "TLS"}
	},
	"proto_no_tls": func(r *model.Report, t *model.TargetReport) {
		protoTarget(t, "ftp", 21)
		t.Proto.TLSMode = "none"
	},
	"ssh_obsolete": func(r *model.Report, t *model.TargetReport) {
		protoTarget(t, "ssh", 22)
		t.Proto.SSH = &model.SSHInfo{Obsolete: []string{"ssh-dss"}}
	},
	"tls_expiring":      func(r *model.Report, t *model.TargetReport) { t.TLS.DaysLeft = 12 },
	"tls_weak":          func(r *model.Report, t *model.TargetReport) { t.TLS.Weak = []string{"TLS 1.0"} },
	"dns_interception":  func(r *model.Report, t *model.TargetReport) { r.DNSGlobal.Intercepted = true },
	"nxdomain_hijack":   func(r *model.Report, t *model.TargetReport) { r.DNSGlobal.NXHijack = true },
	"transparent_proxy": func(r *model.Report, t *model.TargetReport) { t.Proxy.Suspicion = "probable" },
	"path_loss":         func(r *model.Report, t *model.TargetReport) { t.Traces[0].LossFrom = 4 },
	"path_loop":         func(r *model.Report, t *model.TargetReport) { t.Traces[0].Loop = true },
	"dns_fallback":      func(r *model.Report, t *model.TargetReport) { t.DNS.Fallback = true },
}

func has(v model.Verdict, id string) bool {
	for _, f := range v.Findings {
		if f.Rule == id {
			return true
		}
	}
	return false
}

func TestAllOK(t *testing.T) {
	r, tr := base()
	v := Evaluate(r, tr)
	if v.Status != model.OK || len(v.Findings) != 0 || v.Headline.Key != "v.all_ok" {
		t.Errorf("%+v", v)
	}
}

func TestEachRule(t *testing.T) {
	for _, rule := range Rules {
		mut, ok := cases[rule.ID]
		if !ok {
			t.Errorf("règle %s sans test", rule.ID)
			continue
		}
		r, tr := base()
		mut(r, tr)
		v := Evaluate(r, tr)
		if !has(v, rule.ID) {
			var got []string
			for _, f := range v.Findings {
				got = append(got, f.Rule)
			}
			t.Errorf("%s : non déclenchée (constats : %v)", rule.ID, got)
			continue
		}
		// La règle doit porter sa propre gravité et un message.
		for _, f := range v.Findings {
			if f.Rule == rule.ID && (f.Severity != rule.Severity || f.Msg.IsZero()) {
				t.Errorf("%s : constat %+v", rule.ID, f)
			}
		}
	}
	for id := range cases {
		found := false
		for _, r := range Rules {
			found = found || r.ID == id
		}
		if !found {
			t.Errorf("cas %s sans règle", id)
		}
	}
}

// Les causes en amont priment : verdict de tête attendu.
func TestHeadlines(t *testing.T) {
	want := map[string]string{
		"gateway_down":            "v.gateway_down",
		"tcp_timeout_local":       "v.tcp_timeout_local",
		"tcp_timeout_remote_path": "v.tcp_timeout_path",
		"tcp_filtered_at_server":  "v.tcp_filtered_server",
		"smtp25_blocked":          "v.smtp25_blocked",
		"dns_differs":             "v.dns_differs",
		"h3_blocked":              "v.h3_blocked",
	}
	for id, key := range want {
		r, tr := base()
		cases[id](r, tr)
		v := Evaluate(r, tr)
		if v.Headline.Key != key {
			t.Errorf("%s : tête %s, attendu %s", id, v.Headline.Key, key)
		}
	}
}

// Groupes exclusifs : une seule cause TCP.
func TestExclusiveGroups(t *testing.T) {
	r, tr := base()
	cases["smtp25_blocked"](r, tr)
	v := Evaluate(r, tr)
	n := 0
	for _, f := range v.Findings {
		if groups[f.Rule] == "tcp" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d constats TCP", n)
	}
}

func TestSeveritySortAndExit(t *testing.T) {
	r, tr := base()
	tr.DNS.Fallback = true // info
	tr.TLS.DaysLeft = 5    // warn
	v := Evaluate(r, tr)
	if v.Status != model.Warn || v.Findings[0].Rule != "tls_expiring" {
		t.Errorf("%+v", v)
	}
	tr.Verdict = v
	r.Targets = []*model.TargetReport{tr}
	r.ComputeExit()
	if r.ExitCode != 1 {
		t.Errorf("exit %d", r.ExitCode)
	}
	_, ok := base()
	ok.Verdict = Evaluate(r, ok)
	r.Targets = []*model.TargetReport{ok}
	r.ComputeExit()
	if r.ExitCode != 0 {
		t.Errorf("exit %d", r.ExitCode)
	}
	r.Targets[0].Verdict.Status = model.Fail
	r.ComputeExit()
	if r.ExitCode != 2 {
		t.Errorf("exit %d", r.ExitCode)
	}
	_ = time.Now
}

func TestRDPSelfSignedNotFailure(t *testing.T) {
	r, tr := base()
	protoTarget(tr, "rdp", 3389)
	tr.Proto.RDP = &model.RDPInfo{NLARequired: true}
	tr.TLS = &model.TLSResult{Base: model.Base{Status: model.Warn}, SelfSigned: true, Chain: []model.CertInfo{{}}, DaysLeft: 100}
	v := Evaluate(r, tr)
	if has(v, "tls_selfsigned") || has(v, "tls_hostname") {
		t.Errorf("%+v", v.Findings)
	}
}
