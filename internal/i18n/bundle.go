// Socle commun Arpent · Aplomb · Jalon : ce fichier est identique (au chemin
// d'import près) à internal/i18n/i18n.go d'Arpent et d'Aplomb.
//
// Les traductions sont lues dans les fichiers embarqués
// assets/i18n/<langue>.json. Les variables s'écrivent {nom} dans le texte et
// sont passées en paires clé/valeur à Translator.T ; Jalon nomme ses
// variables par position : {1}, {2}…

package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/maxb1906/jalon/assets"
)

// Fallback est la langue utilisée quand une clé manque dans la langue demandée.
const Fallback = "fr"

// Bundle regroupe les catalogues de toutes les langues disponibles.
type Bundle struct {
	catalogs map[string]map[string]string
}

// Load lit tous les fichiers <langue>.json du dossier dir de fsys.
func Load(fsys fs.FS, dir string) (*Bundle, error) {
	files, err := fs.Glob(fsys, path.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("i18n: aucun fichier de traduction dans %q", dir)
	}
	b := &Bundle{catalogs: make(map[string]map[string]string, len(files))}
	for _, f := range files {
		data, err := fs.ReadFile(fsys, f)
		if err != nil {
			return nil, err
		}
		var cat map[string]string
		if err := json.Unmarshal(data, &cat); err != nil {
			return nil, fmt.Errorf("i18n: %s : %w", f, err)
		}
		b.catalogs[strings.TrimSuffix(path.Base(f), ".json")] = cat
	}
	return b, nil
}

var (
	defaultOnce   sync.Once
	defaultBundle *Bundle
	defaultErr    error
)

// Default renvoie le Bundle construit à partir des traductions embarquées.
func Default() (*Bundle, error) {
	defaultOnce.Do(func() {
		defaultBundle, defaultErr = Load(assets.I18n, "i18n")
	})
	return defaultBundle, defaultErr
}

// Languages renvoie les codes de langue disponibles, triés.
func (b *Bundle) Languages() []string {
	langs := make([]string, 0, len(b.catalogs))
	for l := range b.catalogs {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	return langs
}

// Has indique si la langue lang est disponible.
func (b *Bundle) Has(lang string) bool {
	_, ok := b.catalogs[lang]
	return ok
}

// Keys renvoie les clés de la langue lang, triées.
func (b *Bundle) Keys(lang string) []string {
	keys := make([]string, 0, len(b.catalogs[lang]))
	for k := range b.catalogs[lang] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Translator renvoie un traducteur pour lang. Si la langue n'existe pas,
// le traducteur utilise la langue de repli.
func (b *Bundle) Translator(lang string) *Translator {
	if !b.Has(lang) {
		lang = Fallback
	}
	return &Translator{bundle: b, lang: lang}
}

// Translator traduit des clés dans une langue donnée.
type Translator struct {
	bundle *Bundle
	lang   string
}

// Lang renvoie la langue effective du traducteur.
func (t *Translator) Lang() string { return t.lang }

// T traduit key et remplace les variables {nom} par les valeurs données en
// paires : T("hello.greeting", "version", "1.0"). Une clé absente est cherchée
// dans la langue de repli, puis renvoyée telle quelle pour rester visible.
func (t *Translator) T(key string, pairs ...string) string {
	msg, ok := t.bundle.catalogs[t.lang][key]
	if !ok {
		if msg, ok = t.bundle.catalogs[Fallback][key]; !ok {
			msg = key
		}
	}
	if len(pairs) == 0 {
		return msg
	}
	repl := make([]string, 0, len(pairs))
	for i := 0; i+1 < len(pairs); i += 2 {
		repl = append(repl, "{"+pairs[i]+"}", pairs[i+1])
	}
	return strings.NewReplacer(repl...).Replace(msg)
}
