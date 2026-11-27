package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/maxb1906/jalon/internal/engine"
	"github.com/maxb1906/jalon/internal/gui"
	"github.com/maxb1906/jalon/internal/history"
	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/ui/web"
)

// guiShown : la fenêtre a été ouverte et la console libérée ; plus rien à
// afficher dans la console à la sortie.
var guiShown bool

// runGUI ouvre l'interface graphique. Si elle ne peut pas s'ouvrir (hors
// Windows, WebView2 absent, interface non compilée), Jalon se replie sur
// l'UI web locale dans le navigateur.
func runGUI(o cliOpts, opt engine.Options, store *history.Store, l i18n.Lang, dc bool, stdout, stderr io.Writer) int {
	assets := guiAssets()
	if err := gui.Available(assets); err != nil {
		if o.guiSmoke {
			fmt.Fprintln(stderr, err)
			return 2
		}
		key := "gui.fallback_web"
		switch {
		case errors.Is(err, gui.ErrUnsupported):
			key = "gui.fallback_os"
		case errors.Is(err, gui.ErrNoWebView2):
			key = "gui.fallback_webview2"
		}
		fmt.Fprintln(stderr, i18n.T(l, key))
		return web.Serve(web.Config{Options: opt, Store: store, Lang: l, OpenBrowser: !o.noBrowser, Out: stdout, Proto: o.proto})
	}
	app := gui.New(gui.Config{Options: opt, Store: store, Lang: l, Proto: o.proto,
		ReportDir: filepath.Join(os.TempDir(), "jalon-reports")})
	if dc && !o.guiSmoke {
		hideConsole()
		guiShown = true
	}
	if err := gui.Run(app, gui.RunOptions{Assets: assets, Title: "Jalon", Smoke: o.guiSmoke, SmokeTimeout: 90 * time.Second}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	return 0
}
