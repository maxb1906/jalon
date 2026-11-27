// Commande jalon : diagnostic de connectivité et traceroute applicatif.
//
// Copyright (C) 2026 Maxime Boosten — GPL-3.0-or-later.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/report"
	"github.com/maxb1906/jalon/internal/target"
	"github.com/maxb1906/jalon/internal/ui/tui"
	"github.com/maxb1906/jalon/internal/ui/web"
)

func main() {
	args := os.Args[1:]
	dc := doubleClicked()
	if dc && len(args) == 0 {
		// Double clic sous Windows : sans cible, on ouvre l'interface
		// graphique plutôt que d'afficher l'aide dans une fenêtre qui se
		// referme (repli : interface web).
		args = []string{"--gui"}
	}
	code := run(args, dc, os.Stdout, os.Stderr)
	if dc && code != 0 && !guiShown {
		pause(i18n.T(langFromArgs(args), "cli.press_enter"))
	}
	os.Exit(code)
}

// options de la ligne de commande.
type cliOpts struct {
	file       string
	noTrace    bool
	traceMode  string
	ipv4, ipv6 bool
	proto      string
	timeout    time.Duration
	jsonOut    bool
	reportFmt  string
	output     string
	lang       string
	parallel   int
	noHistory  bool
	historyDir string
	web        bool
	gui        bool
	guiSmoke   bool
	tui        bool
	noRDNS     bool
	asn        bool
	h3         bool
	probes     int
	maxHops    int
	ticket     bool
	verbose    bool
	noColor    bool
	version    bool
	parallelTr bool
	noBrowser  bool
}

func newFlagSet(o *cliOpts, l i18n.Lang, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("jalon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	h := func(k string) string { return i18n.T(l, "flag."+k) }
	fs.StringVar(&o.file, "f", "", h("f"))
	fs.BoolVar(&o.noTrace, "no-trace", false, h("no-trace"))
	fs.StringVar(&o.traceMode, "trace-mode", "auto", h("trace-mode"))
	fs.BoolVar(&o.ipv4, "ipv4", false, h("ipv4"))
	fs.BoolVar(&o.ipv4, "4", false, h("ipv4"))
	fs.BoolVar(&o.ipv6, "ipv6", false, h("ipv6"))
	fs.BoolVar(&o.ipv6, "6", false, h("ipv6"))
	fs.StringVar(&o.proto, "proto", "", h("proto"))
	fs.DurationVar(&o.timeout, "timeout", 5*time.Second, h("timeout"))
	fs.BoolVar(&o.jsonOut, "json", false, h("json"))
	fs.StringVar(&o.reportFmt, "report", "", h("report"))
	fs.StringVar(&o.output, "o", "", h("o"))
	fs.StringVar(&o.lang, "lang", "", h("lang"))
	fs.IntVar(&o.parallel, "parallel", 4, h("parallel"))
	fs.BoolVar(&o.parallelTr, "parallel-trace", false, h("parallel-trace"))
	fs.BoolVar(&o.noHistory, "no-history", false, h("no-history"))
	fs.StringVar(&o.historyDir, "history-dir", "", h("history-dir"))
	fs.BoolVar(&o.gui, "gui", false, h("gui"))
	fs.BoolVar(&o.guiSmoke, "gui-smoke", false, h("gui-smoke"))
	fs.BoolVar(&o.web, "web", false, h("web"))
	fs.BoolVar(&o.noBrowser, "no-browser", false, h("no-browser"))
	fs.BoolVar(&o.tui, "tui", false, h("tui"))
	fs.BoolVar(&o.noRDNS, "no-rdns", false, h("no-rdns"))
	fs.BoolVar(&o.asn, "asn", false, h("asn"))
	fs.BoolVar(&o.h3, "h3", false, h("h3"))
	fs.IntVar(&o.probes, "probes", 5, h("probes"))
	fs.IntVar(&o.maxHops, "max-hops", 30, h("max-hops"))
	fs.BoolVar(&o.ticket, "ticket", false, h("ticket"))
	fs.BoolVar(&o.verbose, "v", false, h("v"))
	fs.BoolVar(&o.noColor, "no-color", false, h("no-color"))
	fs.BoolVar(&o.version, "version", false, h("version"))
	fs.Usage = func() {
		fmt.Fprintln(stderr, i18n.T(l, "usage"))
		fs.PrintDefaults()
	}
	return fs
}

// parseInterleaved accepte les options avant ou après les cibles.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// langFromArgs repère --lang avant l'analyse complète (pour l'aide).
func langFromArgs(args []string) i18n.Lang {
	for i, a := range args {
		v := ""
		switch {
		case strings.HasPrefix(a, "--lang=") || strings.HasPrefix(a, "-lang="):
			v = a[strings.Index(a, "=")+1:]
		case (a == "--lang" || a == "-lang") && i+1 < len(args):
			v = args[i+1]
		}
		if v != "" {
			if l, ok := i18n.Parse(v); ok {
				return l
			}
		}
	}
	return i18n.Detect()
}

func run(args []string, dc bool, stdout, stderr io.Writer) int {
	l := langFromArgs(args)
	var o cliOpts
	fs := newFlagSet(&o, l, stderr)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if o.version {
		fmt.Fprintf(stdout, "jalon %s\n", model.Version)
		return 0
	}
	if o.lang != "" {
		if pl, ok := i18n.Parse(o.lang); ok {
			l = pl
		} else {
			fmt.Fprintln(stderr, i18n.T(l, "cli.bad_lang", o.lang))
			return 2
		}
	}
	if len(pos) > 0 {
		switch pos[0] {
		case "history":
			return cmdHistory(o, l, pos[1:], stdout, stderr)
		case "diff":
			return cmdDiff(o, l, pos[1:], stdout, stderr)
		case "version":
			fmt.Fprintf(stdout, "jalon %s\n", model.Version)
			return 0
		case "help":
			fs.Usage()
			return 0
		}
	}

	opt, err := buildOptions(o, l)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var store *history.Store
	if !o.noHistory {
		if s, err := history.Open(o.historyDir); err == nil {
			store = s
		} else {
			fmt.Fprintln(stderr, i18n.T(l, "cli.history_error", err))
		}
	}
	if store != nil {
		opt.PostTarget = HistoryHook(store)
	}

	if o.gui || o.guiSmoke {
		return runGUI(o, opt, store, l, dc, stdout, stderr)
	}
	if o.web {
		return web.Serve(web.Config{Options: opt, Store: store, Lang: l, OpenBrowser: !o.noBrowser, Out: stdout, Proto: o.proto})
	}

	raws := pos
	if o.file != "" {
		var r io.Reader
		if o.file == "-" {
			r = os.Stdin
		} else {
			f, err := os.Open(o.file)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			defer f.Close()
			r = f
		}
		list, err := target.ReadList(r)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		raws = append(raws, list...)
	}
	if len(raws) == 0 {
		fs.Usage()
		return 2
	}
	var targets []model.Target
	for _, r := range raws {
		t, err := target.Parse(r, o.proto)
		if err != nil {
			fmt.Fprintln(stderr, i18n.T(l, "engine.target_error", r+" : "+err.Error()))
			return 2
		}
		targets = append(targets, t)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if o.tui {
		return tui.Run(ctx, opt, targets)
	}

	eng := engine.New(opt)
	tty := isTTY(stdout)
	style := report.Style{Color: tty && !o.noColor && os.Getenv("NO_COLOR") == ""}
	if style.Color {
		enableVT()
	}
	live := tty && !o.jsonOut
	if live {
		attachLive(eng, l, style, len(targets) > 1, o.verbose, stdout)
	} else if isTTY(stderr) && !o.jsonOut {
		attachProgress(eng, l, stderr)
	}
	rep := eng.Run(ctx, targets)

	switch {
	case o.jsonOut && o.output == "":
		if err := report.JSON(stdout, rep); err != nil {
			fmt.Fprintln(stderr, err)
		}
	case o.ticket:
		for _, t := range rep.Targets {
			fmt.Fprint(stdout, report.Ticket(rep, t))
			fmt.Fprintln(stdout)
		}
	default:
		report.Text(stdout, rep, report.TextOptions{Style: style, Verbose: o.verbose, Ticket: true, Live: live})
	}
	if o.reportFmt != "" || (o.jsonOut && o.output != "") {
		format := o.reportFmt
		if format == "" {
			format = "json"
		}
		path, err := writeReport(rep, format, o.output)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintln(stderr, i18n.T(l, "cli.report_written", path))
	}
	return rep.ExitCode
}

func buildOptions(o cliOpts, l i18n.Lang) (engine.Options, error) {
	opt := engine.DefaultOptions()
	opt.Lang = l
	opt.NoTrace = o.noTrace
	switch o.traceMode {
	case "icmp", "tcp", "auto":
		opt.TraceMode = o.traceMode
	default:
		return opt, errors.New(i18n.T(l, "cli.bad_trace_mode", o.traceMode))
	}
	if o.ipv4 && o.ipv6 {
		return opt, errors.New(i18n.T(l, "cli.ipv4_ipv6"))
	}
	opt.IPv4Only, opt.IPv6Only = o.ipv4, o.ipv6
	if o.proto != "" {
		if _, err := target.Parse("x.invalid:1", o.proto); err != nil {
			return opt, errors.New(i18n.T(l, "cli.bad_proto", o.proto, strings.Join(target.Protos, ", ")))
		}
	}
	if o.reportFmt != "" && o.reportFmt != "html" && o.reportFmt != "md" && o.reportFmt != "json" {
		return opt, errors.New(i18n.T(l, "cli.bad_report", o.reportFmt))
	}
	if o.timeout < 500*time.Millisecond {
		o.timeout = 500 * time.Millisecond
	}
	opt.Probe.Timeout = o.timeout
	opt.Parallel = max(1, o.parallel)
	opt.ParallelTrace = o.parallelTr
	opt.Probe.NoRDNS = o.noRDNS
	opt.Probe.ASN = o.asn
	opt.Probe.ForceH3 = o.h3
	opt.Probe.TraceProbes = min(max(1, o.probes), 100)
	opt.Probe.MaxHops = min(max(1, o.maxHops), 64)
	opt.TargetBudget = max(120*time.Second, 20*o.timeout)
	return opt, nil
}

// HistoryHook compare au diagnostic précédent puis enregistre.
func HistoryHook(store *history.Store) func(*model.Report, *model.TargetReport) {
	var mu sync.Mutex
	return func(rep *model.Report, tr *model.TargetReport) {
		mu.Lock()
		defer mu.Unlock()
		net := history.NetworkKey(rep.Env)
		if prev, same := store.Previous(tr.Target.Key(), net, tr.Started); prev != nil {
			tr.Compare = &model.Comparison{PreviousID: prev.ID, PreviousTime: prev.Time, SameNetwork: same,
				Changes: history.Compare(prev.Report, tr)}
		}
		if id, err := store.Save(rep.Env, tr); err == nil {
			tr.HistoryID = id
		}
	}
}

func writeReport(rep *model.Report, format, path string) (string, error) {
	if path == "" {
		path = "jalon-" + rep.Started.Format("20060102-150405") + "." + format
	}
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	switch format {
	case "html":
		err = report.HTML(f, rep)
	case "md":
		report.Markdown(f, rep)
	default:
		err = report.JSON(f, rep)
	}
	if err != nil {
		return "", err
	}
	abs, _ := filepath.Abs(path)
	return abs, nil
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}

// attachLive affiche la cascade au fil de l'eau.
func attachLive(eng *engine.Engine, l i18n.Lang, st report.Style, multi, verbose bool, w io.Writer) {
	eng.Bus.Subscribe(func(e engine.Event) {
		switch e.Type {
		case engine.EvRunStart:
			fmt.Fprintln(w, st.Bold(fmt.Sprintf("Jalon %s", model.Version))+st.Dim(" — "+i18n.T(l, "cli.running", len(e.Targets))))
			fmt.Fprintln(w)
		case engine.EvTargetStart:
			if !multi {
				fmt.Fprintln(w)
				fmt.Fprintln(w, st.Bold("== "+e.Raw+" =="))
			}
		case engine.EvStep:
			prefix := ""
			if multi && e.Target >= 0 {
				prefix = st.Dim("["+strconv.Itoa(e.Target+1)+"] ") + ""
			}
			s := e.Step
			fmt.Fprintf(w, "%s%s %s %s\n", prefix, st.Status(s.Status, report.Icon(s.Status)), padR(i18n.T(l, s.Layer), 24), s.Summary.In(l))
			for _, n := range s.Notes {
				if n.Status == model.Info && !verbose {
					continue
				}
				fmt.Fprintf(w, "%s    %s %s\n", prefix, st.Status(n.Status, report.Icon(n.Status)), n.Msg.In(l))
			}
		}
	})
}

// attachProgress affiche une progression discrète sur stderr.
func attachProgress(eng *engine.Engine, l i18n.Lang, w io.Writer) {
	eng.Bus.Subscribe(func(e engine.Event) {
		if e.Type == engine.EvTargetDone {
			fmt.Fprintf(w, "%s %s\n", report.Icon(e.Report.Verdict.Status), e.Raw)
		}
	})
}

func padR(s string, n int) string {
	r := []rune(s)
	if len(r) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(r))
}

func cmdHistory(o cliOpts, l i18n.Lang, args []string, stdout, stderr io.Writer) int {
	store, err := history.Open(o.historyDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if len(args) > 0 && args[0] == "purge" {
		age := 30 * 24 * time.Hour
		if len(args) > 1 {
			d, err := parseAge(args[1])
			if err != nil {
				fmt.Fprintln(stderr, i18n.T(l, "cli.bad_age", args[1]))
				return 2
			}
			age = d
		}
		n, err := store.Purge(age)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintln(stdout, i18n.T(l, "cli.purged", n, store.Dir))
		return 0
	}
	filter := ""
	if len(args) > 0 {
		filter = args[0]
	}
	list := store.List(filter)
	if o.jsonOut {
		return printJSON(stdout, list)
	}
	fmt.Fprintln(stdout, i18n.T(l, "cli.history_dir", store.Dir))
	if len(list) == 0 {
		fmt.Fprintln(stdout, i18n.T(l, "cli.history_empty"))
		return 0
	}
	for _, m := range list {
		fmt.Fprintf(stdout, "%s  %s  %s %-36s %s\n", m.ID, m.Time.Local().Format("2006-01-02 15:04"), report.Icon(m.Status), m.Raw, m.Headline.In(l))
	}
	return 0
}

// parseAge accepte « 30d », « 12h », « 2w ».
func parseAge(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		v, err := strconv.Atoi(n)
		return time.Duration(v) * 24 * time.Hour, err
	}
	if n, ok := strings.CutSuffix(s, "w"); ok {
		v, err := strconv.Atoi(n)
		return time.Duration(v) * 7 * 24 * time.Hour, err
	}
	return time.ParseDuration(s)
}

func cmdDiff(o cliOpts, l i18n.Lang, args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		fmt.Fprintln(stderr, i18n.T(l, "cli.diff_usage"))
		return 2
	}
	store, err := history.Open(o.historyDir)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	a, err := store.Load(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	b, err := store.Load(args[1])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if a.Time.After(b.Time) {
		a, b = b, a
	}
	changes := history.Compare(a.Report, b.Report)
	if o.jsonOut {
		return printJSON(stdout, map[string]any{"from": a.ID, "to": b.ID, "changes": changes})
	}
	fmt.Fprintln(stdout, i18n.T(l, "cli.diff_header", a.ID, a.Raw, b.ID, b.Raw))
	if a.TargetKey != b.TargetKey {
		fmt.Fprintln(stdout, i18n.T(l, "cli.diff_other_target"))
	}
	if a.Network != b.Network {
		fmt.Fprintln(stdout, i18n.T(l, "text.other_network"))
	}
	if len(changes) == 0 {
		fmt.Fprintln(stdout, i18n.T(l, "text.no_changes"))
	}
	for _, c := range changes {
		fmt.Fprintf(stdout, "%s %s\n", report.Icon(c.Severity), c.Msg.In(l))
	}
	fmt.Fprintf(stdout, "\n%s → %s\n", a.Report.Verdict.Headline.In(l), b.Report.Verdict.Headline.In(l))
	return 0
}
