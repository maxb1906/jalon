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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/maxb1906/jalon/internal/config"
	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/report"
	"github.com/maxb1906/jalon/internal/target"
	"github.com/maxb1906/jalon/internal/ui/tui"
	"github.com/maxb1906/jalon/internal/ui/web"
)

// Codes de sortie : 0, 1 et 2 viennent du diagnostic (OK, avertissement,
// échec) ; exitUsage signale une erreur d'utilisation ou d'exécution de Jalon
// (option invalide, fichier illisible…), pour qu'un script ne la confonde pas
// avec un diagnostic en échec.
const exitUsage = 3

// reportFormats sont les formats acceptés par --format.
var reportFormats = []string{"html", "md", "json", "ticket"}

func main() {
	args := os.Args[1:]
	dc := doubleClicked()
	if dc && len(args) == 0 {
		// Double clic sous Windows : sans cible, on ouvre l'interface web
		// plutôt que d'afficher l'aide dans une fenêtre qui se referme.
		args = []string{"web"}
	}
	code := run(args, os.Stdout, os.Stderr)
	if dc && code != 0 {
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
	format     string
	reportFmt  string // ancien nom de --format
	reportLang string
	output     string
	outDir     string
	lang       string
	data       string
	parallel   int
	noHistory  bool
	historyDir string
	web        bool
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
	fs.StringVar(&o.format, "format", "", h("format"))
	fs.StringVar(&o.reportFmt, "report", "", h("report"))
	fs.StringVar(&o.reportLang, "report-lang", "", h("report-lang"))
	fs.StringVar(&o.output, "o", "", h("o"))
	fs.StringVar(&o.outDir, "out", "", h("out"))
	fs.StringVar(&o.lang, "lang", "", h("lang"))
	fs.StringVar(&o.data, "data", "", h("data"))
	fs.IntVar(&o.parallel, "parallel", 4, h("parallel"))
	fs.BoolVar(&o.parallelTr, "parallel-trace", false, h("parallel-trace"))
	fs.BoolVar(&o.noHistory, "no-history", false, h("no-history"))
	fs.StringVar(&o.historyDir, "history-dir", "", h("history-dir"))
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

// app regroupe ce qui est résolu une fois par exécution : langue,
// configuration et dossier de données (créé seulement s'il sert).
type app struct {
	o      cliOpts
	l      i18n.Lang
	stderr io.Writer
	cfg    config.Config
	cfgDir string // dossier où config.yaml et le logo sont lus
	data   string // dossier de données inscriptible, résolu à la demande
}

// dataDir renvoie le dossier de données, créé au premier besoin.
func (a *app) dataDir() (string, error) {
	if a.data != "" {
		return a.data, nil
	}
	d, fallback, err := config.DataDir(a.o.data)
	if err != nil {
		return "", errors.New(i18n.T(a.l, "cli.data_error", err))
	}
	if fallback {
		fmt.Fprintln(a.stderr, i18n.T(a.l, "cli.data_fallback", d))
	} else {
		_ = config.WriteTemplate(d)
	}
	if old := config.MigrateLegacyHistory(d); old != "" {
		fmt.Fprintln(a.stderr, i18n.T(a.l, "cli.history_migrated", old, config.HistoryDir(d)))
	}
	a.data = d
	return d, nil
}

// historyDir renvoie --history-dir, sinon jalon-data/historique.
func (a *app) historyDir() (string, error) {
	if a.o.historyDir != "" {
		return a.o.historyDir, nil
	}
	d, err := a.dataDir()
	if err != nil {
		return "", err
	}
	return config.HistoryDir(d), nil
}

// openStore ouvre l'historique.
func (a *app) openStore() (*history.Store, error) {
	dir, err := a.historyDir()
	if err != nil {
		return nil, err
	}
	return history.Open(dir)
}

// decorate ajoute la page de garde (technicien, émetteur, logo) au rapport.
func (a *app) decorate(rep *model.Report) {
	rep.Technician = a.cfg.Technician
	if !a.cfg.Issuer.IsZero() {
		is := a.cfg.Issuer
		rep.Issuer = &is
	}
	rep.LogoDataURI = a.cfg.LogoDataURI(a.cfgDir)
}

func run(args []string, stdout, stderr io.Writer) int {
	l := langFromArgs(args)
	var o cliOpts
	fs := newFlagSet(&o, l, stderr)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitUsage
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
			return exitUsage
		}
	}

	a := &app{o: o, l: l, stderr: stderr}
	if dir, _, err := config.Resolve(o.data); err == nil {
		a.cfgDir = dir
		cfg, err := config.Load(dir)
		if err != nil {
			fmt.Fprintln(stderr, i18n.T(l, "cli.config_error", err))
		}
		a.cfg = cfg
	}
	// Langue : --lang, puis JALON_LANG, puis config.yaml, puis le système.
	if o.lang == "" && os.Getenv("JALON_LANG") == "" && a.cfg.Lang != "" {
		if cl, ok := i18n.Parse(a.cfg.Lang); ok {
			l, a.l = cl, cl
		}
	}

	if len(pos) > 0 {
		switch pos[0] {
		case "history":
			return cmdHistory(a, pos[1:], stdout, stderr)
		case "diff":
			return cmdDiff(a, pos[1:], stdout, stderr)
		case "version":
			fmt.Fprintf(stdout, "jalon %s\n", model.Version)
			return 0
		case "help":
			fs.Usage()
			return 0
		case "web":
			o.web, pos = true, pos[1:]
		case "tui":
			o.tui, pos = true, pos[1:]
		}
	}

	// Langue des rapports : --report-lang, puis config.yaml, puis l'outil.
	rl := l
	switch {
	case o.reportLang != "":
		pl, ok := i18n.Parse(o.reportLang)
		if !ok {
			fmt.Fprintln(stderr, i18n.T(l, "cli.bad_lang", o.reportLang))
			return exitUsage
		}
		rl = pl
	case a.cfg.ReportLang != "":
		if pl, ok := i18n.Parse(a.cfg.ReportLang); ok {
			rl = pl
		}
	}
	formats, ok := parseFormats(firstNonEmpty(o.format, o.reportFmt))
	if !ok {
		fmt.Fprintln(stderr, i18n.T(l, "cli.bad_format", firstNonEmpty(o.format, o.reportFmt)))
		return exitUsage
	}
	if len(formats) == 0 && o.jsonOut && o.output != "" {
		formats = []string{"json"} // ancienne forme : --json -o fichier
	}
	if len(formats) > 1 && o.output != "" {
		fmt.Fprintln(stderr, i18n.T(l, "cli.output_multi"))
		return exitUsage
	}

	opt, err := buildOptions(o, l)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	var store *history.Store
	if !o.noHistory {
		if s, err := a.openStore(); err == nil {
			store = s
		} else {
			fmt.Fprintln(stderr, i18n.T(l, "cli.history_error", err))
		}
	}
	if store != nil {
		opt.PostTarget = HistoryHook(store)
	}

	if o.web {
		return web.Serve(web.Config{Options: opt, Store: store, Lang: l, OpenBrowser: !o.noBrowser, Out: stdout, Proto: o.proto, Decorate: a.decorate})
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
				return exitUsage
			}
			defer f.Close()
			r = f
		}
		list, err := target.ReadList(r)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		raws = append(raws, list...)
	}
	if len(raws) == 0 {
		fs.Usage()
		return exitUsage
	}
	var targets []model.Target
	for _, r := range raws {
		t, err := target.Parse(r, o.proto)
		if err != nil {
			fmt.Fprintln(stderr, i18n.T(l, "engine.target_error", r+" : "+err.Error()))
			return exitUsage
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
	if len(formats) > 0 {
		dir := o.outDir
		if dir == "" && o.output == "" {
			d, err := a.dataDir()
			if err != nil {
				fmt.Fprintln(stderr, err)
				return exitUsage
			}
			dir = config.ReportsDir(d)
		}
		cp := *rep
		cp.Lang = rl
		a.decorate(&cp)
		paths, err := writeReports(&cp, formats, dir, o.output)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		for _, p := range paths {
			fmt.Fprintln(stderr, i18n.T(l, "cli.report_written", p))
		}
	}
	return rep.ExitCode
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseFormats lit « html,md,json,ticket » ; false si un format est inconnu.
func parseFormats(s string) ([]string, bool) {
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if !slices.Contains(reportFormats, f) {
			return nil, false
		}
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out, true
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

// writeReports écrit un fichier par format dans dir (jalon-AAAAMMJJ-HHMMSS.<ext>),
// ou dans path s'il est donné (un seul format).
func writeReports(rep *model.Report, formats []string, dir, path string) ([]string, error) {
	var out []string
	base := "jalon-" + rep.Started.Format("20060102-150405")
	if path == "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	for _, format := range formats {
		p := path
		if p == "" {
			ext := format
			if format == "ticket" {
				ext = "txt"
			}
			p = filepath.Join(dir, base+"."+ext)
		}
		if err := writeReport(rep, format, p); err != nil {
			return out, err
		}
		abs, _ := filepath.Abs(p)
		out = append(out, abs)
	}
	return out, nil
}

func writeReport(rep *model.Report, format, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	switch format {
	case "html":
		err = report.HTML(f, rep)
	case "md":
		report.Markdown(f, rep)
	case "ticket":
		for _, t := range rep.Targets {
			if t != nil {
				fmt.Fprintln(f, report.Ticket(rep, t))
			}
		}
	default:
		err = report.JSON(f, rep)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
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

func cmdHistory(a *app, args []string, stdout, stderr io.Writer) int {
	l := a.l
	store, err := a.openStore()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if len(args) > 0 && args[0] == "purge" {
		age := 30 * 24 * time.Hour
		if len(args) > 1 {
			d, err := parseAge(args[1])
			if err != nil {
				fmt.Fprintln(stderr, i18n.T(l, "cli.bad_age", args[1]))
				return exitUsage
			}
			age = d
		}
		n, err := store.Purge(age)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitUsage
		}
		fmt.Fprintln(stdout, i18n.T(l, "cli.purged", n, store.Dir))
		return 0
	}
	filter := ""
	if len(args) > 0 {
		filter = args[0]
	}
	list := store.List(filter)
	if a.o.jsonOut {
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

func cmdDiff(a *app, args []string, stdout, stderr io.Writer) int {
	l := a.l
	if len(args) != 2 {
		fmt.Fprintln(stderr, i18n.T(l, "cli.diff_usage"))
		return exitUsage
	}
	store, err := a.openStore()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	ea, err := store.Load(args[0])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	eb, err := store.Load(args[1])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitUsage
	}
	if ea.Time.After(eb.Time) {
		ea, eb = eb, ea
	}
	changes := history.Compare(ea.Report, eb.Report)
	if a.o.jsonOut {
		return printJSON(stdout, map[string]any{"from": ea.ID, "to": eb.ID, "changes": changes})
	}
	fmt.Fprintln(stdout, i18n.T(l, "cli.diff_header", ea.ID, ea.Raw, eb.ID, eb.Raw))
	if ea.TargetKey != eb.TargetKey {
		fmt.Fprintln(stdout, i18n.T(l, "cli.diff_other_target"))
	}
	if ea.Network != eb.Network {
		fmt.Fprintln(stdout, i18n.T(l, "text.other_network"))
	}
	if len(changes) == 0 {
		fmt.Fprintln(stdout, i18n.T(l, "text.no_changes"))
	}
	for _, c := range changes {
		fmt.Fprintf(stdout, "%s %s\n", report.Icon(c.Severity), c.Msg.In(l))
	}
	fmt.Fprintf(stdout, "\n%s → %s\n", ea.Report.Verdict.Headline.In(l), eb.Report.Verdict.Headline.In(l))
	return 0
}
