// Package assets regroupe les fichiers embarqués dans l'exécutable :
// traductions (assets/i18n/<langue>.json), comme dans Arpent et Aplomb.
package assets

import "embed"

// I18n contient les fichiers de traduction assets/i18n/<langue>.json.
//
//go:embed i18n/*.json
var I18n embed.FS
