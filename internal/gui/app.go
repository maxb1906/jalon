// Package gui est l'interface graphique de Jalon (Wails + WebView2, Windows).
//
// Les méthodes exportées d'App sont appelées par le frontend (frontend/src).
// Elles réutilisent le moteur, l'historique et les rapports, comme la CLI et
// l'UI web. Tout ce qui dépend de la fenêtre (événements, boîtes de dialogue,
// ouverture de fichiers) passe par l'interface Shell : App se teste sous Linux.
package gui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/ui/session"
)

// Événements émis vers le frontend.
const (
	// EventRun porte un événement du moteur : {"run": id, "event": {...}}.
	EventRun = "jalon:event"
	// EventReady est émis par le frontend une fois l'interface initialisée.
	EventReady = "gui:ready"
)

// Shell regroupe ce qui dépend de la fenêtre et du système.
type Shell interface {
	Emit(event string, data any)
	// SaveFile demande où enregistrer un fichier ; "" si l'utilisateur annule.
	SaveFile(title, name, pattern string) (string, error)
	// Open ouvre un fichier ou un dossier avec l'application par défaut.
	Open(path string) error
}

// Config paramètre l'application.
type Config struct {
	Options engine.Options
	Store   *history.Store // nil : historique désactivé
	Lang    i18n.Lang
	Proto   string // protocole forcé par défaut (--proto)
	// ReportDir reçoit les rapports HTML ouverts dans le navigateur
	// (défaut : dossier temporaire).
	ReportDir string
}

// App est l'objet lié au frontend.
type App struct {
	cfg   Config
	shell Shell

	mu      sync.Mutex
	lang    i18n.Lang
	ctx     context.Context
	stop    context.CancelFunc
	current *runState
}

// runState est le diagnostic courant.
type runState struct {
	id     string
	cancel context.CancelFunc
	done   bool
	rep    *model.Report
}

// New crée l'application.
func New(cfg Config) *App {
	ctx, stop := context.WithCancel(context.Background())
	if cfg.Lang == "" {
		cfg.Lang = i18n.FR
	}
	return &App{cfg: cfg, lang: cfg.Lang, ctx: ctx, stop: stop}
}

// SetShell branche la fenêtre (appelé au démarrage de Wails).
func (a *App) SetShell(s Shell) { a.shell = s }

// Shutdown interrompt le diagnostic en cours (fermeture de la fenêtre).
func (a *App) Shutdown() { a.stop() }

// Erreurs renvoyées au frontend.
var (
	ErrBusy      = errors.New("busy")
	ErrNoReport  = errors.New("no report")
	ErrNoShell   = errors.New("no window")
	ErrNoHistory = errors.New("history disabled")
)

func (a *App) emit(name string, data any) {
	if a.shell != nil {
		a.shell.Emit(name, data)
	}
}

func (a *App) curLang() i18n.Lang {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lang
}

// ---- Démarrage et langue ----

// Info est ce dont l'interface a besoin au démarrage.
type Info struct {
	Version    string   `json:"version"`
	Lang       string   `json:"lang"`
	OS         string   `json:"os"`
	HistoryDir string   `json:"history_dir"`
	History    bool     `json:"history"`
	Protos     []string `json:"protos"`
	Proto      string   `json:"proto"`
	TraceMode  string   `json:"trace_mode"`
	NoTrace    bool     `json:"no_trace"`
}

// Protos est la liste des protocoles proposés (en plus de « auto »).
var Protos = []string{"http", "https", "smtp", "imap", "pop3", "ssh", "rdp", "ldap", "ftp", "banner"}

// Init renvoie l'état initial.
func (a *App) Init() Info {
	in := Info{Version: model.Version, Lang: string(a.curLang()), OS: runtime.GOOS, History: a.cfg.Store != nil,
		Protos: Protos, Proto: a.cfg.Proto, TraceMode: a.cfg.Options.TraceMode, NoTrace: a.cfg.Options.NoTrace}
	if a.cfg.Store != nil {
		in.HistoryDir = a.cfg.Store.Dir
	}
	return in
}

// Strings renvoie le catalogue de traductions et adopte la langue demandée.
func (a *App) Strings(lang string) map[string]string {
	l, ok := i18n.Parse(lang)
	if !ok {
		l = a.curLang()
	}
	a.mu.Lock()
	a.lang = l
	a.mu.Unlock()
	return session.Catalog(l)
}

// ---- Diagnostic ----

// Start lance un diagnostic et renvoie son identifiant. Les événements du
// moteur arrivent ensuite sur EventRun ; le dernier est « run_done ».
func (a *App) Start(req session.Request) (string, error) {
	l := a.curLang()
	if pl, ok := i18n.Parse(req.Lang); ok {
		l = pl
	}
	targets, opt, err := session.Prepare(a.cfg.Options, req, a.cfg.Proto, l)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	if a.current != nil && !a.current.done {
		a.mu.Unlock()
		return "", errors.New(i18n.T(l, "gui.busy"))
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	ctx, cancel := context.WithCancel(a.ctx)
	st := &runState{id: hex.EncodeToString(b), cancel: cancel}
	a.current = st
	a.mu.Unlock()

	eng := engine.New(opt)
	eng.Bus.Subscribe(func(e engine.Event) {
		if e.Type == engine.EvRunDone {
			// Le rapport est exportable dès que le frontend reçoit run_done.
			a.finish(st, e.Run)
		}
		// Sérialisé ici, sous le verrou du bus : le moteur peut modifier ses
		// résultats dès le retour de l'abonné.
		if raw, err := json.Marshal(e); err == nil {
			a.emit(EventRun, map[string]any{"run": st.id, "event": json.RawMessage(raw)})
		}
	})
	go func() {
		defer cancel()
		a.finish(st, eng.Run(ctx, targets))
	}()
	return st.id, nil
}

func (a *App) finish(st *runState, rep *model.Report) {
	a.mu.Lock()
	st.rep, st.done = rep, true
	a.mu.Unlock()
}

// Cancel interrompt le diagnostic en cours (les étapes restantes sont
// marquées comme interrompues ; le rapport partiel reste exportable).
func (a *App) Cancel() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current != nil && !a.current.done {
		a.current.cancel()
	}
}

// Running indique si un diagnostic est en cours.
func (a *App) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current != nil && !a.current.done
}

// report renvoie le rapport désigné, dans la langue courante : "" = le
// dernier diagnostic, sinon un identifiant d'historique.
func (a *App) report(id string) (*model.Report, error) {
	l := a.curLang()
	if id == "" {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.current == nil || a.current.rep == nil {
			return nil, ErrNoReport
		}
		cp := *a.current.rep
		cp.Lang = l
		return &cp, nil
	}
	if a.cfg.Store == nil {
		return nil, ErrNoHistory
	}
	e, err := a.cfg.Store.Load(id)
	if err != nil {
		return nil, err
	}
	return session.HistoryReport(e, l), nil
}

// ---- Rapports ----

// Ticket renvoie le résumé ticket (texte brut à coller).
func (a *App) Ticket(id string) (string, error) {
	rep, err := a.report(id)
	if err != nil {
		return "", err
	}
	return session.Ticket(rep), nil
}

// ReportHTML renvoie le rapport HTML autonome (aperçu dans la fenêtre).
func (a *App) ReportHTML(id string) (string, error) {
	rep, err := a.report(id)
	if err != nil {
		return "", err
	}
	b, _, _ := session.Export(rep, "html")
	return string(b), nil
}

// Export enregistre le rapport au format demandé (html, md, json, ticket)
// là où l'utilisateur le choisit. Renvoie le chemin, "" si annulé.
func (a *App) Export(id, format string) (string, error) {
	rep, err := a.report(id)
	if err != nil {
		return "", err
	}
	if a.shell == nil {
		return "", ErrNoShell
	}
	body, ext, _ := session.Export(rep, format)
	name := session.BaseName(rep)
	if id != "" {
		name = "jalon-" + id
	}
	path, err := a.shell.SaveFile(i18n.T(a.curLang(), "gui.save_title"), name+"."+ext, "*."+ext)
	if err != nil || path == "" {
		return "", err
	}
	if filepath.Ext(path) == "" {
		path += "." + ext
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// OpenReport écrit le rapport HTML dans le dossier des rapports et l'ouvre
// dans le navigateur par défaut. Renvoie le chemin du fichier.
func (a *App) OpenReport(id string) (string, error) {
	rep, err := a.report(id)
	if err != nil {
		return "", err
	}
	if a.shell == nil {
		return "", ErrNoShell
	}
	dir := a.cfg.ReportDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "jalon-reports")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := session.BaseName(rep)
	if id != "" {
		name = "jalon-" + id
	}
	path := filepath.Join(dir, name+"-"+string(rep.Lang)+".html")
	body, _, _ := session.Export(rep, "html")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return "", err
	}
	return path, a.shell.Open(path)
}

// ---- Historique ----

// History liste les diagnostics enregistrés, filtrés par cible.
func (a *App) History(filter string) []session.HistoryItem {
	return session.HistoryList(a.cfg.Store, filter, a.curLang())
}

// LoadHistory renvoie un diagnostic enregistré, pour l'afficher comme un
// diagnostic qui vient de se terminer.
func (a *App) LoadHistory(id string) (*model.Report, error) {
	return a.report(id)
}

// Diff compare deux diagnostics enregistrés.
func (a *App) Diff(idA, idB string) (*session.DiffResult, error) {
	return session.Diff(a.cfg.Store, idA, idB, a.curLang())
}

// OpenHistoryDir ouvre le dossier d'historique dans l'explorateur.
func (a *App) OpenHistoryDir() error {
	if a.cfg.Store == nil {
		return ErrNoHistory
	}
	if a.shell == nil {
		return ErrNoShell
	}
	return a.shell.Open(a.cfg.Store.Dir)
}
