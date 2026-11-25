// Package i18n fournit les messages FR/EN de Jalon, lus dans les catalogues
// JSON embarqués (assets/i18n/fr.json et en.json) par le socle commun à
// Arpent et Aplomb (bundle.go).
//
// Les messages s'écrivent avec des variables positionnelles {1}, {2}… Un
// argument « @clé » est lui-même traduit.
package i18n

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Lang est une langue supportée.
type Lang string

const (
	FR Lang = "fr"
	EN Lang = "en"
)

// Msg est un message traduisible : une clé de catalogue et ses arguments
// (déjà formatés en chaînes, pour un aller-retour JSON sans perte).
type Msg struct {
	Key  string   `json:"key"`
	Args []string `json:"args,omitempty"`
}

// M construit un message ; les arguments sont convertis avec fmt.Sprint.
func M(key string, args ...any) Msg {
	m := Msg{Key: key}
	for _, a := range args {
		m.Args = append(m.Args, fmt.Sprint(a))
	}
	return m
}

// IsZero indique si le message est vide.
func (m Msg) IsZero() bool { return m.Key == "" }

// T traduit une clé dans la langue demandée.
func T(l Lang, key string, args ...any) string {
	return M(key, args...).In(l)
}

// bundle renvoie les catalogues embarqués ; une erreur de lecture est un bug
// de construction (détecté par les tests).
func bundle() *Bundle {
	b, err := Default()
	if err != nil {
		panic(err)
	}
	return b
}

// lookup cherche une clé dans la langue demandée puis dans la langue de repli.
func (b *Bundle) lookup(l Lang, key string) (string, bool) {
	if s, ok := b.catalogs[string(l)][key]; ok {
		return s, true
	}
	s, ok := b.catalogs[Fallback][key]
	return s, ok
}

// In rend le message dans la langue demandée. Une clé inconnue est rendue
// telle quelle (avec ses arguments), jamais de panique.
func (m Msg) In(l Lang) string {
	b := bundle()
	if _, ok := b.lookup(l, m.Key); !ok {
		if len(m.Args) == 0 {
			return m.Key
		}
		return m.Key + " " + strings.Join(m.Args, " ")
	}
	pairs := make([]string, 0, 2*len(m.Args))
	for i, s := range m.Args {
		// « @clé » : argument lui-même traduit.
		if len(s) > 1 && s[0] == '@' {
			if _, ok := b.lookup(l, s[1:]); ok {
				s = T(l, s[1:])
			}
		}
		pairs = append(pairs, strconv.Itoa(i+1), s)
	}
	return b.Translator(string(l)).T(m.Key, pairs...)
}

// Parse convertit une chaîne en langue (défaut : FR).
func Parse(s string) (Lang, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case strings.HasPrefix(s, "fr"):
		return FR, true
	case strings.HasPrefix(s, "en"):
		return EN, true
	}
	return FR, false
}

// Detect devine la langue de l'utilisateur à partir de l'environnement
// (JALON_LANG, LC_ALL, LC_MESSAGES, LANG) puis de l'OS. Défaut : anglais si
// la langue détectée n'est pas le français, français si rien n'est trouvé.
func Detect() Lang {
	for _, v := range []string{"JALON_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if s := os.Getenv(v); s != "" && s != "C" && s != "POSIX" && !strings.HasPrefix(s, "C.") {
			if l, ok := Parse(s); ok {
				return l
			}
			return EN
		}
	}
	if s := osLocale(); s != "" {
		if l, ok := Parse(s); ok {
			return l
		}
		return EN
	}
	return FR
}

// Keys renvoie toutes les clés du catalogue (pour les tests et l'UI web).
func Keys() []string { return bundle().Keys(Fallback) }

// Raw renvoie le texte d'une clé sans remplacer les variables (UI web).
func Raw(l Lang, key string) string {
	if s, ok := bundle().lookup(l, key); ok {
		return s
	}
	return key
}

// Prefixed renvoie les traductions des clés commençant par prefix.
func Prefixed(l Lang, prefix string) map[string]string {
	out := map[string]string{}
	for _, k := range Keys() {
		if strings.HasPrefix(k, prefix) {
			out[k] = T(l, k)
		}
	}
	return out
}
