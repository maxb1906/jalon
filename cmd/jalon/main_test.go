package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
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

func TestRunErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if c := run([]string{"--version"}, false, &out, &errb); c != 0 || !strings.Contains(out.String(), "jalon") {
		t.Errorf("version %d", c)
	}
	if c := run([]string{"--trace-mode", "x", "a.test"}, false, &out, &errb); c != 2 {
		t.Errorf("mode invalide %d", c)
	}
	if c := run([]string{"--no-history", "gopher://x"}, false, &out, &errb); c != 2 {
		t.Errorf("cible invalide %d", c)
	}
	if c := run([]string{"--lang", "de"}, false, &out, &errb); c != 2 {
		t.Errorf("langue invalide %d", c)
	}
	if c := run([]string{"history", "--history-dir", t.TempDir()}, false, &out, &errb); c != 0 {
		t.Errorf("history %d", c)
	}
}
