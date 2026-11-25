package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

func TestParseInterleaved(t *testing.T) {
	var o cliOpts
	fs := newFlagSet(&o, i18n.FR, io.Discard)
	pos, err := parseInterleaved(fs, []string{"https://a.test", "--json", "b.test", "--timeout", "2s", "--", "-c"})
	if err != nil || len(pos) != 3 || pos[1] != "b.test" || pos[2] != "-c" || !o.jsonOut || o.timeout != 2*time.Second {
		t.Errorf("%v %v %+v", pos, err, o)
	}
}

func TestParseAge(t *testing.T) {
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "12h": 12 * time.Hour} {
		if d, err := parseAge(in); err != nil || d != want {
			t.Errorf("%s → %v %v", in, d, err)
		}
	}
	if _, err := parseAge("x"); err == nil {
		t.Error("x accepté")
	}
}

// Les erreurs d'utilisation renvoient 3, jamais 2 (réservé au diagnostic en échec).
func TestRunErrors(t *testing.T) {
	t.Setenv("JALON_DATA", t.TempDir())
	var out, errb bytes.Buffer
	if c := run([]string{"--version"}, &out, &errb); c != 0 || !strings.Contains(out.String(), "jalon") {
		t.Errorf("version %d", c)
	}
	for _, args := range [][]string{
		{"--trace-mode", "x", "a.test"},
		{"--no-history", "gopher://x"},
		{"--lang", "de"},
		{"--no-history", "--format", "pdf", "a.test"},
		{"--no-history", "--report-lang", "de", "a.test"},
		{"--no-history", "--format", "html,md", "-o", "x.html", "a.test"},
		{"--option-inconnue"},
		{"diff", "un-seul-id"},
		{"--no-history"},
	} {
		if c := run(args, &out, &errb); c != exitUsage {
			t.Errorf("%v : code %d, attendu %d", args, c, exitUsage)
		}
	}
	if c := run([]string{"history", "--history-dir", t.TempDir()}, &out, &errb); c != 0 {
		t.Errorf("history %d", c)
	}
}

func TestParseFormats(t *testing.T) {
	if f, ok := parseFormats(" HTML, md,json ,ticket,html"); !ok || !slices.Equal(f, []string{"html", "md", "json", "ticket"}) {
		t.Errorf("%v %v", f, ok)
	}
	if f, ok := parseFormats(""); !ok || f != nil {
		t.Errorf("vide : %v %v", f, ok)
	}
	if _, ok := parseFormats("html,pdf"); ok {
		t.Error("pdf accepté")
	}
}

func TestWriteReports(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rapports")
	rep := &model.Report{Tool: "jalon", Lang: i18n.EN, Started: time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)}
	paths, err := writeReports(rep, []string{"html", "md", "json", "ticket"}, dir, "")
	if err != nil || len(paths) != 4 {
		t.Fatalf("%v %v", paths, err)
	}
	for _, ext := range []string{".html", ".md", ".json", ".txt"} {
		if _, err := os.Stat(filepath.Join(dir, "jalon-20261125-100000"+ext)); err != nil {
			t.Errorf("%s absent", ext)
		}
	}
	one := filepath.Join(t.TempDir(), "r.json")
	if paths, err := writeReports(rep, []string{"json"}, "", one); err != nil || len(paths) != 1 {
		t.Errorf("-o : %v %v", paths, err)
	}
}

// Les rapports vont dans jalon-data/rapports et l'historique dans
// jalon-data/historique ; config.yaml est créé avec le dossier.
func TestDataLayout(t *testing.T) {
	data := t.TempDir()
	a := &app{o: cliOpts{data: data}, l: i18n.FR, stderr: io.Discard}
	h, err := a.historyDir()
	if err != nil || h != filepath.Join(data, "historique") {
		t.Fatalf("%q %v", h, err)
	}
	if _, err := os.Stat(filepath.Join(data, "config.yaml")); err != nil {
		t.Error("config.yaml non créé")
	}
}
