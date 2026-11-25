package i18n

import "fmt"

// catalog associe une clé à sa traduction {FR, EN}. Il est alimenté par les
// fichiers catalog_*.go ; une clé déclarée deux fois provoque une panique au
// démarrage (détectée par les tests).
var catalog = map[string][2]string{}

func add(m map[string][2]string) bool {
	for k, v := range m {
		if _, dup := catalog[k]; dup {
			panic(fmt.Sprintf("i18n: clé dupliquée %q", k))
		}
		catalog[k] = v
	}
	return true
}
