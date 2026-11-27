//go:build !windows

package gui

import "io/fs"

// Available : l'interface graphique n'existe que sous Windows (Wails y est
// pur Go ; sous Linux et macOS il exigerait cgo). Ailleurs : --web ou --tui.
func Available(fs.FS) error { return ErrUnsupported }

// Run n'est disponible que sous Windows.
func Run(*App, RunOptions) error { return ErrUnsupported }
