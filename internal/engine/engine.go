package engine

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/probe"
	"github.com/maxb1906/jalon/internal/probe/proto"
	"github.com/maxb1906/jalon/internal/verdict"
)

// Options paramètre une exécution.
type Options struct {
	Probe         probe.Config
	Lang          i18n.Lang
	NoTrace       bool
	TraceMode     string // icmp, tcp, auto
	IPv4Only      bool
	IPv6Only      bool
	Parallel      int
	ParallelTrace bool          // par défaut, les traceroutes sont sérialisés
	TargetBudget  time.Duration // budget global par cible
	NoGlobal      bool          // pas d'interception DNS ni de portail captif (tests)
	// PostTarget est appelé avant la publication de target_done (historique).
	PostTarget func(*model.Report, *model.TargetReport)
}

// DefaultOptions renvoie les options par défaut.
func DefaultOptions() Options {
	return Options{
		Probe:        probe.DefaultConfig(),
		Lang:         i18n.FR,
		TraceMode:    "auto",
		Parallel:     4,
		TargetBudget: 120 * time.Second,
	}
}

// Engine exécute la cascade.
type Engine struct {
	Opt     Options
	Bus     *Bus
	traceMu sync.Mutex
}

// New crée un moteur.
func New(opt Options) *Engine {
	if opt.Parallel < 1 {
		opt.Parallel = 1
	}
	return &Engine{Opt: opt, Bus: &Bus{}}
}

func (e *Engine) emitStep(idx int, raw string, s model.Step) {
	e.Bus.Emit(Event{Type: EvStep, Target: idx, Raw: raw, StepID: s.ID, Step: &s})
}

func (e *Engine) emitStart(idx int, raw, id string) {
	e.Bus.Emit(Event{Type: EvStepStart, Target: idx, Raw: raw, StepID: id})
}

// Run exécute le diagnostic complet sur les cibles.
func (e *Engine) Run(ctx context.Context, targets []model.Target) *model.Report {
	rep := &model.Report{Tool: "jalon", Version: model.Version, Lang: e.Opt.Lang, Started: time.Now()}
	raws := make([]string, len(targets))
	for i, t := range targets {
		raws[i] = t.Raw
	}
	e.Bus.Emit(Event{Type: EvRunStart, Target: -1, Targets: raws})

	// 1. Environnement local (une seule fois).
	e.emitStart(-1, "", "env")
	rep.Env = probe.Env(ctx, e.Opt.Probe)
	cfg := e.Opt.Probe
	cfg.Env = rep.Env
	e.emitStep(-1, "", model.Step{ID: "env", Layer: "layer.env", Base: &rep.Env.Base})

	// 2. Interception DNS et portail captif (une seule fois, en parallèle).
	if !e.Opt.NoGlobal {
		sample := ""
		for _, t := range targets {
			if !t.IsIP {
				sample = t.Host
				break
			}
		}
		var wg sync.WaitGroup
		wg.Add(2)
		e.emitStart(-1, "", "dns_global")
		e.emitStart(-1, "", "captive")
		go func() {
			defer wg.Done()
			rep.DNSGlobal = probe.DNSGlobal(ctx, cfg, sample)
		}()
		go func() {
			defer wg.Done()
			rep.Captive = probe.Captive(ctx, cfg)
		}()
		wg.Wait()
		if rep.DNSGlobal.WhoamiCF != "" {
			rep.Env.PublicIP = rep.DNSGlobal.WhoamiCF
		}
		e.emitStep(-1, "", model.Step{ID: "dns_global", Layer: "layer.dns_global", Base: &rep.DNSGlobal.Base})
		e.emitStep(-1, "", model.Step{ID: "captive", Layer: "layer.captive", Base: &rep.Captive.Base})
	}

	// 3. Cibles, en parallèle avec une limite de concurrence.
	rep.Targets = make([]*model.TargetReport, len(targets))
	sem := make(chan struct{}, e.Opt.Parallel)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			tr := e.runTarget(ctx, cfg, rep, i, t)
			rep.Targets[i] = tr
		}()
	}
	wg.Wait()
	rep.Finished = time.Now()
	rep.ComputeExit()
	e.Bus.Emit(Event{Type: EvRunDone, Target: -1, Run: rep})
	return rep
}

func (e *Engine) runTarget(ctx context.Context, cfg probe.Config, rep *model.Report, idx int, t model.Target) *model.TargetReport {
	e.Bus.Emit(Event{Type: EvTargetStart, Target: idx, Raw: t.Raw})
	tctx, cancel := context.WithTimeout(ctx, e.Opt.TargetBudget)
	defer cancel()
	tr := RunCascade(tctx, e, cfg, idx, t)
	tr.Verdict = verdict.Evaluate(rep, tr)
	if e.Opt.PostTarget != nil {
		e.Opt.PostTarget(rep, tr)
	}
	tr.Finished = time.Now()
	e.Bus.Emit(Event{Type: EvTargetDone, Target: idx, Raw: t.Raw, Report: tr})
	return tr
}

// RunCascade déroule les couches d'une cible.
func RunCascade(ctx context.Context, e *Engine, cfg probe.Config, idx int, t model.Target) *model.TargetReport {
	tr := &model.TargetReport{Target: t, Started: time.Now()}
	raw := t.Raw
	step := func(s model.Step) { e.emitStep(idx, raw, s) }

	// DNS.
	var v4, v6 []string
	host := t.Host
	dnsMs := 0.0
	if t.IsIP {
		if probe.IsV6(t.Host) {
			v6 = []string{t.Host}
		} else {
			v4 = []string{t.Host}
		}
	} else {
		e.emitStart(idx, raw, "dns")
		tr.DNS = probe.DNS(ctx, cfg, t)
		step(model.Step{ID: "dns", Layer: "layer.dns", Base: &tr.DNS.Base})
		v4, v6 = tr.DNS.IPv4, tr.DNS.IPv6
		if tr.DNS.ConnectHost != "" {
			host = tr.DNS.ConnectHost
		}
		for _, a := range tr.DNS.Answers {
			if a.Resolver == "os" || a.Resolver == "system" {
				dnsMs = max(dnsMs, a.RTTMs)
				break
			}
		}
	}

	// TCP v4 / v6 en parallèle.
	e.emitStart(idx, raw, "tcp")
	var t4, t6 *model.TCPResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if e.Opt.IPv6Only {
			t4 = skippedTCP("ipv4", t.Port)
			return
		}
		t4 = probe.TCP(ctx, cfg, "ipv4", v4, t.Port)
	}()
	go func() {
		defer wg.Done()
		if e.Opt.IPv4Only {
			t6 = skippedTCP("ipv6", t.Port)
			return
		}
		t6 = probe.TCP(ctx, cfg, "ipv6", v6, t.Port)
	}()
	wg.Wait()
	probe.TCPAdjust(t4, t6)
	tr.TCP = []*model.TCPResult{t4, t6}
	step(model.Step{ID: "tcp_ipv4", Layer: "layer.tcp_ipv4", Base: &t4.Base})
	step(model.Step{ID: "tcp_ipv6", Layer: "layer.tcp_ipv6", Base: &t6.Base})

	// Adresse retenue pour la suite : IPv6 si elle marche (comme l'OS),
	// sinon IPv4.
	switch {
	case t6.Outcome == "connected" && !e.Opt.IPv4Only:
		tr.ChosenIP = t6.IP
	case t4.Outcome == "connected":
		tr.ChosenIP = t4.IP
	}

	// Couche applicative.
	switch t.Proto {
	case "http", "https":
		if t.Proto == "https" {
			if tr.ChosenIP == "" {
				tr.TLS = &model.TLSResult{}
				tr.TLS.Skip("engine.skipped_no_tcp")
			} else {
				e.emitStart(idx, raw, "tls")
				tr.TLS = probe.TLSDial(ctx, cfg, tr.ChosenIP, t.Port, host, probe.TLSOptions{ALPN: []string{"h2", "http/1.1"}})
			}
			step(model.Step{ID: "tls", Layer: "layer.tls", Base: &tr.TLS.Base})
		}
		if tr.ChosenIP == "" {
			tr.HTTP = &model.HTTPResult{}
			tr.HTTP.Skip("engine.skipped_no_tcp")
		} else {
			e.emitStart(idx, raw, "http")
			tr.HTTP = probe.HTTP(ctx, cfg, t, tr.ChosenIP, dnsMs)
		}
		step(model.Step{ID: "http", Layer: "layer.http", Base: &tr.HTTP.Base})
		if t.Proto == "https" {
			if tr.ChosenIP == "" {
				tr.HTTP3 = &model.HTTP3Result{}
				tr.HTTP3.Skip("engine.skipped_no_tcp")
			} else {
				e.emitStart(idx, raw, "http3")
				tr.HTTP3 = probe.HTTP3(ctx, cfg, t, tr.ChosenIP, tr.HTTP.H3Advertised, tr.HTTP.H3Port)
			}
			step(model.Step{ID: "http3", Layer: "layer.http3", Base: &tr.HTTP3.Base})
		}
	default:
		if tr.ChosenIP == "" {
			tr.Proto = &model.ProtoResult{Proto: t.Proto}
			tr.Proto.Skip("engine.skipped_no_tcp")
		} else {
			e.emitStart(idx, raw, "proto")
			tr.Proto, tr.TLS = proto.Run(ctx, cfg, t, tr.ChosenIP, host)
		}
		step(model.Step{ID: "proto", Layer: "layer.proto." + t.Proto, Base: &tr.Proto.Base})
		if tr.TLS != nil {
			step(model.Step{ID: "tls", Layer: "layer.tls", Base: &tr.TLS.Base})
		}
	}

	// Chemin réseau.
	if !e.Opt.NoTrace {
		dest := tr.ChosenIP
		if dest == "" {
			switch {
			case len(v4) > 0 && !e.Opt.IPv6Only:
				dest = v4[0]
			case len(v6) > 0 && !e.Opt.IPv4Only:
				dest = v6[0]
			}
		}
		if dest != "" {
			e.runTraces(ctx, cfg, idx, tr, dest, t.Port)
		}
	}

	// Heuristiques de proxy transparent.
	if t.Proto == "http" || t.Proto == "https" {
		if tr.ChosenIP != "" {
			e.emitStart(idx, raw, "proxy")
			tr.Proxy = probe.Proxy(ctx, cfg, t, tr.ChosenIP, tr.HTTP, tr.Traces)
			step(model.Step{ID: "proxy", Layer: "layer.proxy", Base: &tr.Proxy.Base})
		}
	}
	tr.Finished = time.Now()
	return tr
}

func skippedTCP(fam string, port int) *model.TCPResult {
	r := &model.TCPResult{Family: fam, Port: port, Outcome: "excluded"}
	r.Skip("engine.skipped_family")
	return r
}

// traceModes renvoie les modes à exécuter.
func traceModes(mode string) []string {
	switch mode {
	case "icmp":
		return []string{"icmp"}
	case "tcp":
		return []string{"tcp"}
	}
	return []string{"icmp", "tcp"}
}

func (e *Engine) runTraces(ctx context.Context, cfg probe.Config, idx int, tr *model.TargetReport, dest string, port int) {
	if !e.Opt.ParallelTrace {
		e.traceMu.Lock()
		defer e.traceMu.Unlock()
	}
	modes := traceModes(e.Opt.TraceMode)
	// TCP demandé mais indisponible : repli ICMP, la raison est affichée.
	if e.Opt.TraceMode == "tcp" && !cfg.Env.Priv.TCPTrace && !slices.Contains(modes, "icmp") {
		modes = append(modes, "icmp")
	}
	results := make([]*model.TraceResult, len(modes))
	var wg sync.WaitGroup
	for i, m := range modes {
		wg.Add(1)
		e.emitStart(idx, tr.Target.Raw, "trace_"+m)
		go func() {
			defer wg.Done()
			results[i] = probe.Trace(ctx, cfg, m, dest, port, func(live *model.TraceResult) {
				e.Bus.Emit(Event{Type: EvTrace, Target: idx, Raw: tr.Target.Raw, StepID: "trace_" + m, Trace: live})
			})
		}()
	}
	wg.Wait()
	probe.CompareTraces(results)
	tr.Traces = results
	for _, r := range results {
		e.emitStep(idx, tr.Target.Raw, model.Step{ID: "trace_" + r.Mode, Layer: "layer.trace_" + r.Mode, Base: &r.Base})
	}
}
