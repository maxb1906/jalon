// Package web fournit l'UI web locale : serveur HTTP sur 127.0.0.1
// uniquement, port aléatoire, jeton dans l'URL, suivi en direct (SSE),
// historique, comparaison et export. Les fichiers sont embarqués dans le
// binaire : aucun CDN externe.
package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/report"
	"github.com/maxb1906/jalon/internal/ui/session"
)

//go:embed assets
var assets embed.FS

// Config paramètre le serveur web.
type Config struct {
	Options     engine.Options
	Store       *history.Store
	Lang        i18n.Lang
	OpenBrowser bool
	Out         io.Writer
	Proto       string
	Addr        string // tests : adresse d'écoute (défaut 127.0.0.1:0)
}

// runState conserve les événements d'une exécution pour les rejouer.
type runState struct {
	mu     sync.Mutex
	events [][]byte
	subs   map[chan []byte]bool
	done   bool
	rep    *model.Report
}

func (r *runState) push(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, b)
	for ch := range r.subs {
		select {
		case ch <- b:
		default:
		}
	}
}

// Server est l'UI web.
type Server struct {
	cfg   Config
	token string
	port  int
	mu    sync.Mutex
	runs  map[string]*runState
	ctx   context.Context
}

// New crée le serveur (sans l'écouter).
func New(cfg Config) *Server {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	if cfg.Out == nil {
		cfg.Out = io.Discard
	}
	return &Server{cfg: cfg, token: hex.EncodeToString(b), runs: map[string]*runState{}, ctx: context.Background()}
}

// Token renvoie le jeton d'accès.
func (s *Server) Token() string { return s.token }

// Serve lance le serveur jusqu'à Ctrl+C et renvoie le code de sortie.
func Serve(cfg Config) int {
	s := New(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	s.ctx = ctx
	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(cfg.Out, err)
		return 2
	}
	s.port = ln.Addr().(*net.TCPAddr).Port
	url := fmt.Sprintf("http://127.0.0.1:%d/?t=%s", s.port, s.token)
	fmt.Fprintln(cfg.Out, i18n.T(cfg.Lang, "web.listening", url))
	if cfg.OpenBrowser {
		openBrowser(url)
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(cfg.Out, err)
		return 2
	}
	return 0
}

// openBrowser ouvre l'URL dans le navigateur par défaut.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// Handler renvoie le routeur HTTP protégé.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(assets, "assets")
	static := http.FileServerFS(sub)
	mux.HandleFunc("GET /{$}", s.index)
	mux.Handle("GET /static/", http.StripPrefix("/static/", static))
	mux.HandleFunc("GET /api/i18n", s.apiI18n)
	mux.HandleFunc("POST /api/run", s.apiRun)
	mux.HandleFunc("GET /api/events", s.apiEvents)
	mux.HandleFunc("GET /api/report", s.apiReport)
	mux.HandleFunc("GET /api/history", s.apiHistory)
	mux.HandleFunc("GET /api/history/report", s.apiHistoryReport)
	mux.HandleFunc("GET /api/diff", s.apiDiff)
	return s.guard(mux)
}

// guard vérifie l'hôte (anti DNS-rebinding) et le jeton.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.Host)
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			tok := r.URL.Query().Get("t")
			if tok == "" {
				tok = r.Header.Get("X-Jalon-Token")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(s.token)) != 1 {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) lang(r *http.Request) i18n.Lang {
	if l, ok := i18n.Parse(r.URL.Query().Get("lang")); ok {
		return l
	}
	return s.cfg.Lang
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	b, _ := assets.ReadFile("assets/index.html")
	tpl, err := template.New("i").Parse(string(b))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	l := s.lang(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, map[string]any{
		"Token": s.token, "Lang": string(l), "Version": model.Version,
		"CSS": template.CSS(report.CSS), "Title": i18n.T(l, "web.title"),
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (s *Server) apiI18n(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, session.Catalog(s.lang(r)))
}

func (s *Server) apiRun(w http.ResponseWriter, r *http.Request) {
	var req session.Request
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	l := s.lang(r)
	if pl, ok := i18n.Parse(req.Lang); ok {
		l = pl
	}
	targets, opt, err := session.Prepare(s.cfg.Options, req, s.cfg.Proto, l)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	id := hex.EncodeToString(b)
	st := &runState{subs: map[chan []byte]bool{}}
	s.mu.Lock()
	s.runs[id] = st
	s.mu.Unlock()
	eng := engine.New(opt)
	eng.Bus.Subscribe(func(e engine.Event) {
		if b, err := json.Marshal(e); err == nil {
			st.push(b)
		}
	})
	go func() {
		rep := eng.Run(s.ctx, targets)
		st.mu.Lock()
		st.rep, st.done = rep, true
		for ch := range st.subs {
			close(ch)
		}
		st.subs = map[chan []byte]bool{}
		st.mu.Unlock()
	}()
	writeJSON(w, map[string]string{"id": id})
}

func (s *Server) getRun(id string) *runState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runs[id]
}

// apiEvents diffuse les événements d'une exécution en Server-Sent Events,
// en rejouant d'abord ceux déjà émis.
func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	st := s.getRun(r.URL.Query().Get("id"))
	if st == nil {
		http.NotFound(w, r)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := make(chan []byte, 1024)
	st.mu.Lock()
	backlog := append([][]byte{}, st.events...)
	done := st.done
	if !done {
		st.subs[ch] = true
	}
	st.mu.Unlock()
	for _, b := range backlog {
		fmt.Fprintf(w, "data: %s\n\n", b)
	}
	fl.Flush()
	if done {
		fmt.Fprint(w, "event: end\ndata: {}\n\n")
		fl.Flush()
		return
	}
	defer func() {
		st.mu.Lock()
		delete(st.subs, ch)
		st.mu.Unlock()
	}()
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keep.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case b, ok := <-ch:
			if !ok {
				fmt.Fprint(w, "event: end\ndata: {}\n\n")
				fl.Flush()
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		}
	}
}

func writeExport(w http.ResponseWriter, rep *model.Report, format, name string) {
	body, ext, ctype := session.Export(rep, format)
	w.Header().Set("Content-Type", ctype)
	if format != "html" || name != "" {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.%s"`, firstNon(name, session.BaseName(rep)), ext))
	}
	_, _ = w.Write(body)
}

func firstNon(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Server) apiReport(w http.ResponseWriter, r *http.Request) {
	st := s.getRun(r.URL.Query().Get("id"))
	if st == nil {
		http.NotFound(w, r)
		return
	}
	st.mu.Lock()
	rep := st.rep
	st.mu.Unlock()
	if rep == nil {
		http.Error(w, "running", http.StatusConflict)
		return
	}
	cp := *rep
	cp.Lang = s.lang(r)
	name := ""
	if r.URL.Query().Get("download") == "1" {
		name = session.BaseName(rep)
	}
	writeExport(w, &cp, r.URL.Query().Get("format"), name)
}

func (s *Server) apiHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, session.HistoryList(s.cfg.Store, r.URL.Query().Get("q"), s.lang(r)))
}

func (s *Server) apiHistoryReport(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Store == nil {
		http.NotFound(w, r)
		return
	}
	e, err := s.cfg.Store.Load(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	rep := session.HistoryReport(e, s.lang(r))
	name := ""
	if r.URL.Query().Get("download") == "1" {
		name = e.ID
	}
	writeExport(w, rep, firstNon(r.URL.Query().Get("format"), "html"), name)
}

func (s *Server) apiDiff(w http.ResponseWriter, r *http.Request) {
	d, err := session.Diff(s.cfg.Store, r.URL.Query().Get("a"), r.URL.Query().Get("b"), s.lang(r))
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	writeJSON(w, d)
}
