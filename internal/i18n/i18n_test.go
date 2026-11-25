package i18n

import (
	"strings"
	"testing"
)

func TestCatalogComplete(t *testing.T) {
	for k, v := range catalog {
		if v[0] == "" || v[1] == "" {
			t.Errorf("%s : traduction vide", k)
		}
		if n0, n1 := strings.Count(v[0], "%s"), strings.Count(v[1], "%s"); n0 != n1 {
			t.Errorf("%s : %d %%s en FR, %d en EN", k, n0, n1)
		}
		for _, s := range v {
			r := strings.NewReplacer("%s", "", "%%", "").Replace(s)
			if strings.Contains(r, "%") {
				t.Errorf("%s : verbe de format autre que %%s : %q", k, s)
			}
		}
	}
}

func TestIn(t *testing.T) {
	if got := T(FR, "tcp.connected", "1.2.3.4", 443, "12.5"); got != "1.2.3.4 port 443 : connecté en 12.5 ms" {
		t.Errorf("FR = %q", got)
	}
	if got := T(EN, "tcp.connected", "1.2.3.4", 443, "12.5"); !strings.HasPrefix(got, "1.2.3.4 port 443: connected") {
		t.Errorf("EN = %q", got)
	}
	if got := T(FR, "clé.inconnue", "x"); got != "clé.inconnue x" {
		t.Errorf("inconnue = %q", got)
	}
	m := Msg{Key: "chg.layer_warn", Args: []string{"@col.dns"}}
	if got := m.In(EN); got != "layer DNS: new warning" {
		t.Errorf("@ = %q", got)
	}
}

func TestParseDetect(t *testing.T) {
	if l, ok := Parse("en_US.UTF-8"); !ok || l != EN {
		t.Error("en_US")
	}
	if l, ok := Parse("fr-BE"); !ok || l != FR {
		t.Error("fr-BE")
	}
	t.Setenv("JALON_LANG", "en")
	if Detect() != EN {
		t.Error("JALON_LANG")
	}
	t.Setenv("JALON_LANG", "")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "de_DE.UTF-8")
	if Detect() != EN {
		t.Error("de → en")
	}
}
