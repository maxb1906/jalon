package gui

import (
	"errors"
	"io/fs"
	"time"
)

// Erreurs de lancement : l'appelant se replie alors sur l'UI web.
var (
	ErrUnsupported = errors.New("graphical interface only available on Windows")
	ErrNoWebView2  = errors.New("WebView2 runtime not installed")
	ErrNoFrontend  = errors.New("graphical interface not built")
)

// RunOptions règle la fenêtre.
type RunOptions struct {
	Assets fs.FS
	Title  string
	// Smoke ferme la fenêtre dès que l'interface est prête (test de
	// lancement) ; Run échoue si elle ne l'est pas avant SmokeTimeout.
	Smoke        bool
	SmokeTimeout time.Duration
}

// hasIndex indique que l'interface a été compilée.
func hasIndex(assets fs.FS) bool {
	if assets == nil {
		return false
	}
	_, err := fs.Stat(assets, "index.html")
	return err == nil
}
