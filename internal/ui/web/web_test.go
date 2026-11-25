package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
)

func newTest(t *testing.T) (*Server, *httptest.Server) {
	opt := engine.DefaultOptions()
	opt.NoGlobal, opt.NoTrace = true, true
	opt.Probe.Timeout = time.Second
	store, _ := history.Open(t.TempDir())
	s := New(Config{Options: opt, Store: store, Lang: i18n.FR})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return s, ts
}

func TestGuard(t *testing.T) {
	s, ts := newTest(t)
	r, _ := http.Get(ts.URL + "/")
	if r.StatusCode != 401 {
		t.Errorf("sans jeton : %d", r.StatusCode)
	}
	r, _ = http.Get(ts.URL + "/?t=" + s.Token())
	if r.StatusCode != 200 || r.Header.Get("Content-Security-Policy") == "" {
		t.Errorf("avec jeton : %d", r.StatusCode)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/?t="+s.Token(), nil)
	req.Host = "evil.example:80"
	r, _ = http.DefaultClient.Do(req)
	if r.StatusCode != 403 {
		t.Errorf("hôte étranger : %d", r.StatusCode)
	}
	r, _ = http.Get(ts.URL + "/static/app.js")
	if r.StatusCode != 200 {
		t.Errorf("statique : %d", r.StatusCode)
	}
}

func TestRunAndEvents(t *testing.T) {
	s, ts := newTest(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer up.Close()
	port := up.Listener.Addr().(*net.TCPAddr).Port
	body := fmt.Sprintf(`{"targets":"http://127.0.0.1:%d/"}`, port)
	r, err := http.Post(ts.URL+"/api/run?t="+s.Token(), "application/json", strings.NewReader(body))
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("%v %d", err, r.StatusCode)
	}
	var res map[string]string
	json.NewDecoder(r.Body).Decode(&res)
	ev, err := http.Get(ts.URL + "/api/events?t=" + s.Token() + "&id=" + res["id"])
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(ev.Body)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var types []string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "event: end") {
			break
		}
		if d, ok := strings.CutPrefix(line, "data: "); ok {
			var e engine.Event
			json.Unmarshal([]byte(d), &e)
			types = append(types, string(e.Type))
		}
	}
	if len(types) < 3 || types[0] != "run_start" || types[len(types)-1] != "run_done" {
		t.Errorf("événements %v", types)
	}
	for _, f := range []string{"html", "md", "json", "ticket"} {
		r, _ := http.Get(ts.URL + "/api/report?t=" + s.Token() + "&id=" + res["id"] + "&format=" + f)
		if r.StatusCode != 200 {
			t.Errorf("export %s : %d", f, r.StatusCode)
		}
	}
	r, _ = http.Get(ts.URL + "/api/history?t=" + s.Token())
	var hist []map[string]any
	json.NewDecoder(r.Body).Decode(&hist)
	_ = hist // l'historique n'est alimenté que par le crochet de la CLI
	r, _ = http.Post(ts.URL+"/api/run?t="+s.Token(), "application/json", strings.NewReader(`{"targets":""}`))
	if r.StatusCode != 400 {
		t.Errorf("cible vide : %d", r.StatusCode)
	}
}

func TestI18nEndpoint(t *testing.T) {
	s, ts := newTest(t)
	r, _ := http.Get(ts.URL + "/api/i18n?lang=en&t=" + s.Token())
	var m map[string]string
	json.NewDecoder(r.Body).Decode(&m)
	if m["web.run"] != "Run diagnosis" {
		t.Errorf("%q", m["web.run"])
	}
}

func TestGuardPort(t *testing.T) {
	s, ts := newTest(t)
	s.port = ts.Listener.Addr().(*net.TCPAddr).Port
	r, err := http.Get(ts.URL + "/?t=" + s.Token())
	if err != nil || r.StatusCode != 200 {
		t.Fatalf("bon port : %v %v", err, r)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/?t="+s.Token(), nil)
	req.Host = fmt.Sprintf("127.0.0.1:%d", s.port+1)
	if r, _ = http.DefaultClient.Do(req); r.StatusCode != 403 {
		t.Errorf("autre port : %d", r.StatusCode)
	}
}
