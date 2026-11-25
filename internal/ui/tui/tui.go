// Package tui fournit l'interface terminal : cascade qui se remplit en
// direct, panneau MTR live (gelable) et navigation entre cibles.
package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/probe"
	"github.com/maxb1906/jalon/internal/report"
)

var (
	stOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	stWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	stFail  = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	stInfo  = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	stDim   = lipgloss.NewStyle().Faint(true)
	stBold  = lipgloss.NewStyle().Bold(true)
	stTab   = lipgloss.NewStyle().Padding(0, 1)
	stTabOn = lipgloss.NewStyle().Padding(0, 1).Reverse(true)
	stBox   = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
)

func styleFor(s model.Status) lipgloss.Style {
	switch s {
	case model.OK:
		return stOK
	case model.Warn:
		return stWarn
	case model.Fail:
		return stFail
	case model.Info:
		return stInfo
	}
	return stDim
}

// targetState est l'état affiché d'une cible.
type targetState struct {
	raw     string
	steps   []model.Step
	running string
	traces  map[string]*model.TraceResult
	report  *model.TargetReport
	done    bool
}

type evMsg engine.Event
type liveMsg struct {
	idx int
	tr  *model.TraceResult
}
type tickMsg time.Time

type uiModel struct {
	lang    i18n.Lang
	opt     engine.Options
	targets []*targetState
	global  []model.Step
	gRun    string
	sel     int
	showMTR bool
	frozen  bool
	verbose bool
	done    bool
	run     *model.Report
	width   int
	height  int
	spin    int
	prog    *tea.Program
	liveCtx context.CancelFunc
	liveMu  *sync.Mutex
	liveIdx int
	scroll  int
}

// Run lance la TUI et renvoie le code de sortie.
func Run(ctx context.Context, opt engine.Options, targets []model.Target) int {
	m := &uiModel{lang: opt.Lang, opt: opt, liveMu: &sync.Mutex{}, liveIdx: -1}
	for _, t := range targets {
		m.targets = append(m.targets, &targetState{raw: t.Raw, traces: map[string]*model.TraceResult{}})
	}
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithContext(ctx))
	m.prog = p
	eng := engine.New(opt)
	eng.Bus.Subscribe(func(e engine.Event) { p.Send(evMsg(e)) })
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan *model.Report, 1)
	go func() { done <- eng.Run(rctx, targets) }()
	final, err := p.Run()
	if fm, ok := final.(*uiModel); ok && fm.liveCtx != nil {
		fm.liveCtx()
	}
	var rep *model.Report
	select {
	case rep = <-done:
	default:
		cancel() // sortie avant la fin : on interrompt le diagnostic
		rep = <-done
	}
	if err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	for _, t := range rep.Targets {
		if t != nil {
			fmt.Print(report.Ticket(rep, t))
			fmt.Println()
		}
	}
	return rep.ExitCode
}

func tick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *uiModel) Init() tea.Cmd { return tick() }

func (m *uiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		m.spin++
		return m, tick()
	case evMsg:
		m.onEvent(engine.Event(msg))
	case liveMsg:
		if !m.frozen && msg.idx >= 0 && msg.idx < len(m.targets) {
			m.targets[msg.idx].traces[msg.tr.Mode] = msg.tr
		}
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "right", "tab", "l", "n":
			if len(m.targets) > 0 {
				m.sel = (m.sel + 1) % len(m.targets)
				m.scroll = 0
			}
		case "left", "shift+tab", "h", "p":
			if len(m.targets) > 0 {
				m.sel = (m.sel - 1 + len(m.targets)) % len(m.targets)
				m.scroll = 0
			}
		case "m":
			m.showMTR = !m.showMTR
			m.scroll = 0
			if m.showMTR && m.done {
				m.startLive()
			}
		case " ", "f":
			m.frozen = !m.frozen
		case "v":
			m.verbose = !m.verbose
		case "down", "j":
			m.scroll++
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		}
	}
	return m, nil
}

func (m *uiModel) onEvent(e engine.Event) {
	var ts *targetState
	if e.Target >= 0 && e.Target < len(m.targets) {
		ts = m.targets[e.Target]
	}
	switch e.Type {
	case engine.EvStepStart:
		if ts == nil {
			m.gRun = e.StepID
		} else {
			ts.running = e.StepID
		}
	case engine.EvStep:
		if ts == nil {
			m.global = append(m.global, *e.Step)
			m.gRun = ""
		} else {
			ts.steps = append(ts.steps, *e.Step)
			ts.running = ""
		}
	case engine.EvTrace:
		if ts != nil && !m.frozen {
			ts.traces[e.Trace.Mode] = e.Trace
		}
	case engine.EvTargetDone:
		if ts != nil {
			ts.report, ts.done, ts.running = e.Report, true, ""
			for _, t := range e.Report.Traces {
				ts.traces[t.Mode] = t
			}
		}
	case engine.EvRunDone:
		m.done, m.run = true, e.Run
		if m.showMTR {
			m.startLive()
		}
	}
}

// startLive lance un MTR continu vers la cible sélectionnée.
func (m *uiModel) startLive() {
	m.liveMu.Lock()
	defer m.liveMu.Unlock()
	if m.liveIdx == m.sel && m.liveCtx != nil {
		return
	}
	if m.liveCtx != nil {
		m.liveCtx()
		m.liveCtx = nil
	}
	ts := m.targets[m.sel]
	if ts.report == nil || m.run == nil || m.run.Env == nil {
		return
	}
	var dest string
	var mode string
	for _, t := range ts.report.Traces {
		if t.Available && dest == "" {
			dest, mode = t.Dest, t.Mode
		}
	}
	if dest == "" {
		return
	}
	cfg := m.opt.Probe
	cfg.Env = m.run.Env
	ctx, cancel := context.WithCancel(context.Background())
	m.liveCtx, m.liveIdx = cancel, m.sel
	idx, port, prog := m.sel, ts.report.Target.Port, m.prog
	go probe.TraceRounds(ctx, cfg, mode, dest, port, 0, func(tr *model.TraceResult) {
		probe.AnalyzeTrace(tr)
		prog.Send(liveMsg{idx: idx, tr: tr})
	})
}

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (m *uiModel) t(k string, a ...any) string { return i18n.T(m.lang, k, a...) }

func (m *uiModel) View() string {
	var b strings.Builder
	title := stBold.Render("Jalon "+model.Version) + stDim.Render(" — "+m.t("tui.subtitle"))
	b.WriteString(title + "\n")
	// Étapes communes, sur une ligne chacune.
	for _, s := range m.global {
		b.WriteString(m.stepLine(s, "") + "\n")
	}
	if m.gRun != "" {
		b.WriteString(stDim.Render(spinner[m.spin%len(spinner)]+" "+m.t("layer."+m.gRun)) + "\n")
	}
	b.WriteString("\n")
	// Onglets.
	var tabs []string
	for i, ts := range m.targets {
		icon := spinner[m.spin%len(spinner)]
		st := model.Skipped
		if ts.done {
			st = ts.report.Verdict.Status
			icon = report.Icon(st)
		}
		label := styleFor(st).Render(icon) + " " + truncate(ts.raw, 28)
		if i == m.sel {
			tabs = append(tabs, stTabOn.Render(label))
		} else {
			tabs = append(tabs, stTab.Render(label))
		}
	}
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Top, tabs...) + "\n\n")

	var body []string
	if len(m.targets) > 0 {
		ts := m.targets[m.sel]
		if m.showMTR {
			body = m.mtrLines(ts)
		} else {
			body = m.cascadeLines(ts)
		}
	}
	avail := m.height - strings.Count(b.String(), "\n") - 2
	if avail < 5 {
		avail = 5
	}
	if m.scroll > max(0, len(body)-avail) {
		m.scroll = max(0, len(body)-avail)
	}
	end := min(len(body), m.scroll+avail)
	for _, l := range body[m.scroll:end] {
		b.WriteString(l + "\n")
	}
	keys := m.t("tui.keys")
	if m.frozen {
		keys = stWarn.Render(m.t("tui.frozen")) + "  " + keys
	}
	b.WriteString(stDim.Render(keys))
	return b.String()
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func (m *uiModel) stepLine(s model.Step, indent string) string {
	st := styleFor(s.Status)
	name := m.t(s.Layer)
	pad := 24 - len([]rune(name))
	if pad < 1 {
		pad = 1
	}
	line := indent + st.Render(report.Icon(s.Status)) + " " + name + strings.Repeat(" ", pad) + s.Summary.In(m.lang)
	if m.width > 10 {
		line = truncateANSI(line, m.width)
	}
	return line
}

// truncateANSI coupe une ligne trop longue (largeur visible).
func truncateANSI(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(w).Render(s)
}

func (m *uiModel) cascadeLines(ts *targetState) []string {
	var out []string
	if ts.done {
		v := ts.report.Verdict
		box := styleFor(v.Status).Render(report.Icon(v.Status) + " " + v.Headline.In(m.lang))
		if len(v.Findings) > 0 && v.Status != model.OK && !v.Findings[0].Advice.IsZero() {
			box += "\n→ " + v.Findings[0].Advice.In(m.lang)
		}
		for i, f := range v.Findings {
			if i == 0 && v.Status != model.OK {
				continue
			}
			box += "\n" + styleFor(f.Severity).Render(report.Icon(f.Severity)) + " " + f.Msg.In(m.lang)
		}
		w := m.width - 4
		if w < 20 {
			w = 76
		}
		for _, l := range strings.Split(stBox.Width(w).Render(box), "\n") {
			out = append(out, l)
		}
		out = append(out, "")
	}
	for _, s := range ts.steps {
		out = append(out, m.stepLine(s, "  "))
		for _, n := range s.Notes {
			if n.Status == model.Info && !m.verbose {
				continue
			}
			l := "      " + styleFor(n.Status).Render(report.Icon(n.Status)) + " " + n.Msg.In(m.lang)
			if n.Status == model.Info {
				l = stDim.Render("      " + report.Icon(n.Status) + " " + n.Msg.In(m.lang))
			}
			out = append(out, truncateANSI(l, max(m.width, 40)))
		}
	}
	if ts.running != "" {
		out = append(out, stDim.Render("  "+spinner[m.spin%len(spinner)]+" "+m.t("tui.running", m.t(layerOf(ts.running)))))
	}
	if !ts.done && ts.running == "" && len(ts.steps) == 0 {
		out = append(out, stDim.Render("  "+m.t("tui.waiting")))
	}
	if ts.done && ts.report.Compare != nil {
		out = append(out, "", stBold.Render("  "+m.t("text.changes", ts.report.Compare.PreviousTime.Local().Format("2006-01-02 15:04"))))
		if len(ts.report.Compare.Changes) == 0 {
			out = append(out, "    "+m.t("text.no_changes"))
		}
		for _, c := range ts.report.Compare.Changes {
			out = append(out, "    "+styleFor(c.Severity).Render(report.Icon(c.Severity))+" "+c.Msg.In(m.lang))
		}
	}
	return out
}

func layerOf(id string) string {
	switch id {
	case "tcp":
		return "col.tcp"
	case "proto":
		return "col.app"
	}
	return "layer." + id
}

func (m *uiModel) mtrLines(ts *targetState) []string {
	var out []string
	if len(ts.traces) == 0 {
		return []string{stDim.Render("  " + m.t("tui.no_trace"))}
	}
	for _, mode := range []string{"icmp", "tcp"} {
		tr := ts.traces[mode]
		if tr == nil {
			continue
		}
		head := m.t("layer.trace_" + mode)
		if m.liveIdx == m.sel && m.liveCtx != nil && !m.frozen {
			head += " " + stInfo.Render("● "+m.t("tui.live"))
		}
		out = append(out, stBold.Render("  "+head))
		if !tr.Available {
			out = append(out, "    "+stDim.Render(tr.Summary.In(m.lang)), "")
			continue
		}
		var sb strings.Builder
		report.HopsText(&sb, m.lang, tr, "    ")
		for _, l := range strings.Split(strings.TrimRight(sb.String(), "\n"), "\n") {
			out = append(out, l)
		}
		if !tr.Summary.IsZero() {
			out = append(out, "    "+styleFor(tr.Status).Render(report.Icon(tr.Status))+" "+tr.Summary.In(m.lang))
		}
		out = append(out, "")
	}
	return out
}
