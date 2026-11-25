package i18n

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

var placeholder = regexp.MustCompile(`\{[0-9]+\}`)

// Même nom de test qu'Arpent et Aplomb : une traduction manquante, vide ou
// dont les variables diffèrent fait échouer la CI.
func TestEmbeddedCatalogsAreComplete(t *testing.T) {
	b, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Languages(); !slices.Equal(got, []string{"en", "fr"}) {
		t.Fatalf("langues = %v", got)
	}
	fr, en := b.Keys("fr"), b.Keys("en")
	if !slices.Equal(fr, en) {
		t.Errorf("clés différentes : %d en FR, %d en EN", len(fr), len(en))
	}
	for _, k := range fr {
		vf, _ := b.lookup(FR, k)
		ve, ok := b.catalogs["en"][k]
		if !ok {
			t.Errorf("%s : absente en EN", k)
			continue
		}
		if vf == "" || ve == "" {
			t.Errorf("%s : traduction vide", k)
		}
		pf, pe := placeholder.FindAllString(vf, -1), placeholder.FindAllString(ve, -1)
		slices.Sort(pf)
		slices.Sort(pe)
		if !slices.Equal(pf, pe) {
			t.Errorf("%s : variables %v en FR, %v en EN", k, pf, pe)
		}
		for _, s := range []string{vf, ve} {
			if strings.Contains(s, "%s") {
				t.Errorf("%s : ancien format %%s : %q", k, s)
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
	// Un argument qui contient « {2} » n'est pas réinterprété.
	if got := T(EN, "tcp.connected", "{2}", 443, "1"); !strings.HasPrefix(got, "{2} port 443") {
		t.Errorf("argument réinterprété : %q", got)
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
