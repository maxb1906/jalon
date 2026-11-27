//go:build !windows

package main

import "io/fs"

// guiAssets : pas d'interface graphique hors Windows (Wails y exigerait cgo),
// donc rien à embarquer ; --gui se replie sur l'interface web.
func guiAssets() fs.FS { return nil }
