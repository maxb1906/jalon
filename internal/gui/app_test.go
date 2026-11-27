package gui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/ui/session"
)

// fakeShell enregistre les événements et simule les boîtes de dialogue.
type fakeShell struct {
	mu       sync.Mutex
	events   []map[string]any
	done     chan struct{}
	savePath string
	opened   []string
}

func newShell() *fakeShell { return &fakeShell{done: make(chan struct{})} }

func (f *fakeShell) Emit(name string, data any) {
	if name != EventRun {
		return
	}
	// Même chemin que Wails : sérialisation JSON de la charge utile.
	b, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	f.mu.Lock()
	f.events = append(f.events, m)
	f.mu.Unlock()
	if ev, _ := m["event"].(map[string]any); ev["type"] == "run_done" {
		close(f.done)
	}
}

func (f *fakeShell) SaveFile(_, name, _ string) (string, error) {
	if f.savePath == "" {
		return "", nil
	}
	return filepath.Join(f.savePath, name), nil
}

func (f *fakeShell) Open(p string) error {
	f.mu.Lock()
	f.opened = append(f.opened, p)
	f.mu.Unlock()
	return nil
}

func newApp(t *testing.T, store *history.Store) (*App, *fakeShell) {
	opt := engine.DefaultOptions()
	opt.NoGlobal, opt.NoTrace = true, true
	opt.Probe.Timeout = time.Second
	if store != nil {
		opt.PostTarget = func(rep *model.Report, tr *model.TargetReport) {
			if id, err := store.Save(rep.Env, tr); err == nil {
				tr.HistoryID = id
			}
		}
	}
	a := New(Config{Options: opt, Store: store, Lang: i18n.FR, ReportDir: t.TempDir()})
	sh := newShell()
	a.SetShell(sh)
	return a, sh
}

func localTarget(t *testing.T) string {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	t.Cleanup(up.Close)
	return fmt.Sprintf("http://127.0.0.1:%d/", up.Listener.Addr().(*net.TCPAddr).Port)
}

func wait(t *testing.T, sh *fakeShell) {
	select {
	case <-sh.done:
	case <-time.After(60 * time.Second):
		t.Fatal("run_done non reçu")
	}
}

func TestStartEventsAndExports(t *testing.T) {
	store, _ := history.Open(t.TempDir())
	a, sh := newApp(t, store)
	id, err := a.Start(session.Request{Targets: localTarget(t)})
	if err != nil || id == "" {
		t.Fatalf("Start : %q %v", id, err)
	}
	wait(t, sh)
	if a.Running() {
		t.Error("toujours en cours après run_done")
	}
	sh.mu.Lock()
	var types []string
	for _, m := range sh.events {
		if m["run"] != id {
			t.Errorf("identifiant d'exécution %v ≠ %s", m["run"], id)
		}
		types = append(types, m["event"].(map[string]any)["type"].(string))
	}
	sh.mu.Unlock()
	if len(types) < 4 || types[0] != "run_start" || types[len(types)-1] != "run_done" {
		t.Errorf("événements %v", types)
	}

	// Exports du diagnostic courant.
	if tk, err := a.Ticket(""); err != nil || !strings.Contains(tk, "127.0.0.1") {
		t.Errorf("ticket : %v %q", err, tk)
	}
	if h, err := a.ReportHTML(""); err != nil || !strings.HasPrefix(strings.ToLower(h), "<!doctype html") {
		t.Errorf("html : %v", err)
	}
	if p, err := a.Export("", "md"); err != nil || p != "" {
		t.Errorf("export annulé : %q %v", p, err)
	}
	sh.savePath = t.TempDir()
	for _, f := range []string{"html", "md", "json", "ticket"} {
		p, err := a.Export("", f)
		if err != nil || p == "" {
			t.Fatalf("export %s : %q %v", f, p, err)
		}
		if b, _ := os.ReadFile(p); len(b) == 0 {
			t.Errorf("export %s vide", f)
		}
	}
	p, err := a.OpenReport("")
	if err != nil || len(sh.opened) != 1 || sh.opened[0] != p {
		t.Errorf("OpenReport : %q %v %v", p, err, sh.opened)
	}

	// Historique : liste, rechargement, comparaison.
	list := a.History("")
	if len(list) != 1 || list[0].Text == "" {
		t.Fatalf("historique %+v", list)
	}
	rep, err := a.LoadHistory(list[0].ID)
	if err != nil || len(rep.Targets) != 1 || rep.Env == nil {
		t.Fatalf("LoadHistory : %v", err)
	}
	if tk, err := a.Ticket(list[0].ID); err != nil || tk == "" {
		t.Errorf("ticket historique : %v", err)
	}
	if _, err := a.Diff(list[0].ID, list[0].ID); err != nil {
		t.Errorf("Diff : %v", err)
	}
	if _, err := a.Diff(list[0].ID, "absent"); err == nil {
		t.Error("Diff vers une entrée absente")
	}
	if err := a.OpenHistoryDir(); err != nil || sh.opened[len(sh.opened)-1] != store.Dir {
		t.Errorf("OpenHistoryDir : %v", err)
	}
}

func TestStartErrors(t *testing.T) {
	a, _ := newApp(t, nil)
	if _, err := a.Start(session.Request{Targets: "  \n# rien\n"}); err == nil {
		t.Error("cible vide acceptée")
	}
	if _, err := a.Start(session.Request{Targets: "gopher://x"}); err == nil {
		t.Error("schéma inconnu accepté")
	}
	if _, err := a.Ticket(""); !errors.Is(err, ErrNoReport) {
		t.Errorf("ticket sans diagnostic : %v", err)
	}
	if _, err := a.LoadHistory("x"); !errors.Is(err, ErrNoHistory) {
		t.Errorf("historique désactivé : %v", err)
	}
	if got := a.History(""); got == nil || len(got) != 0 {
		t.Errorf("historique désactivé : %v", got)
	}
}

func TestBusyAndCancel(t *testing.T) {
	// Cible qui ne répond jamais (TEST-NET) : le diagnostic dure jusqu'à l'annulation.
	a, sh := newApp(t, nil)
	if _, err := a.Start(session.Request{Targets: "https://192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Start(session.Request{Targets: "https://192.0.2.2"}); err == nil {
		t.Error("deux diagnostics simultanés")
	}
	a.Cancel()
	wait(t, sh)
	if a.Running() {
		t.Error("toujours en cours après annulation")
	}
}

func TestStringsSetsLang(t *testing.T) {
	a, _ := newApp(t, nil)
	if m := a.Strings("en"); m["web.run"] != "Run diagnosis" {
		t.Errorf("%q", m["web.run"])
	}
	if a.Init().Lang != "en" {
		t.Error("langue non adoptée")
	}
	if m := a.Strings("xx"); m["web.run"] != "Run diagnosis" {
		t.Error("langue inconnue : la langue courante doit rester")
	}
}

func TestAvailableWithoutFrontend(t *testing.T) {
	if err := Available(os.DirFS(t.TempDir())); err == nil {
		t.Error("interface absente acceptée")
	}
}

// TestFrontendKeysExist vérifie que chaque clé de traduction utilisée par le
// frontend (t('…') littéral, ou préfixe dynamique connu) existe en FR et EN.
func TestFrontendKeysExist(t *testing.T) {
	root := filepath.Join("..", "..", "frontend", "src")
	known := map[string]bool{}
	for _, k := range i18n.Keys() {
		known[k] = true
	}
	lit := regexp.MustCompile(`\bt\('([a-z0-9_.]+)'[,)]`)
	dyn := regexp.MustCompile(`\bt\('([a-z0-9_.]+)' \+`)
	// Préfixes dynamiques autorisés et suffixes possibles.
	suffixes := map[string][]string{
		"status.":    {"ok", "info", "warn", "fail", "skipped"},
		"col.":       {"dns", "tcp", "tls", "app", "trace"},
		"layer.":     {"env", "dns_global", "captive"},
		"gui.layer_": {"env", "dns", "trace", "tcp", "tls", "app", "captive", "env_desc", "dns_desc", "trace_desc", "tcp_desc", "tls_desc", "app_desc", "captive_desc"},
	}
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(p, "mock") {
			return err
		}
		if ext := filepath.Ext(p); ext != ".svelte" && ext != ".ts" {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range lit.FindAllStringSubmatch(string(b), -1) {
			n++
			if !known[m[1]] {
				t.Errorf("%s : clé inconnue %q", p, m[1])
			}
		}
		for _, m := range dyn.FindAllStringSubmatch(string(b), -1) {
			s, ok := suffixes[m[1]]
			if !ok {
				t.Errorf("%s : préfixe dynamique non déclaré %q", p, m[1])
			}
			for _, x := range s {
				if !known[m[1]+x] {
					t.Errorf("%s : clé inconnue %q", p, m[1]+x)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 30 {
		t.Errorf("seulement %d clés trouvées : frontend absent ?", n)
	}
}
