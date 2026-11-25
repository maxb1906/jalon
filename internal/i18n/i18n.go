// Package i18n fournit les catalogues de messages FR/EN embarqués.
package i18n

import (
	"fmt"
	"os"
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

// In rend le message dans la langue demandée. Une clé inconnue est rendue
// telle quelle (avec ses arguments), jamais de panique.
func (m Msg) In(l Lang) string {
	e, ok := catalog[m.Key]
	if !ok {
		if len(m.Args) == 0 {
			return m.Key
		}
		return m.Key + " " + strings.Join(m.Args, " ")
	}
	f := e[0]
	if l == EN {
		f = e[1]
	}
	if len(m.Args) == 0 {
		return f
	}
	a := make([]any, len(m.Args))
	for i, s := range m.Args {
		// « @clé » : argument lui-même traduit.
		if len(s) > 1 && s[0] == '@' {
			if _, ok := catalog[s[1:]]; ok {
				a[i] = T(l, s[1:])
				continue
			}
		}
		a[i] = s
	}
	return fmt.Sprintf(f, a...)
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
func Keys() []string {
	k := make([]string, 0, len(catalog))
	for key := range catalog {
		k = append(k, key)
	}
	return k
}

// Prefixed renvoie les traductions des clés commençant par prefix.
func Prefixed(l Lang, prefix string) map[string]string {
	out := map[string]string{}
	for k := range catalog {
		if strings.HasPrefix(k, prefix) {
			out[k] = T(l, k)
		}
	}
	return out
}
