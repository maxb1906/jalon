//go:build windows

package gui

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wailsapp/go-webview2/webviewloader"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
	xwindows "golang.org/x/sys/windows"
)

// minWebView2 est la version minimale du runtime WebView2 exigée par Wails.
const minWebView2 = "94.0.992.31"

// webView2Version renvoie la version du runtime WebView2 installée ("" si
// absent ou trop ancien).
func webView2Version() string {
	v, err := webviewloader.GetAvailableCoreWebView2BrowserVersionString("")
	if err != nil || v == "" {
		return ""
	}
	if c, err := webviewloader.CompareBrowserVersions(v, minWebView2); err != nil || c < 0 {
		return ""
	}
	return v
}

// Available indique si la fenêtre peut s'ouvrir (WebView2 et interface compilée).
func Available(assets fs.FS) error {
	if !hasIndex(assets) {
		return ErrNoFrontend
	}
	if webView2Version() == "" {
		return ErrNoWebView2
	}
	return nil
}

// Run ouvre la fenêtre et rend la main à sa fermeture.
func Run(a *App, o RunOptions) error {
	if err := Available(o.Assets); err != nil {
		return err
	}
	sh := &shell{}
	a.SetShell(sh)
	var smokeErr error
	err := wails.Run(&options.App{
		Title:            o.Title,
		Width:            1280,
		Height:           860,
		MinWidth:         980,
		MinHeight:        640,
		AssetServer:      &assetserver.Options{Assets: o.Assets},
		BackgroundColour: &options.RGBA{R: 246, G: 247, B: 249, A: 255},
		OnStartup: func(ctx context.Context) {
			sh.ctx = ctx
			if o.Smoke {
				timeout := o.SmokeTimeout
				if timeout == 0 {
					timeout = time.Minute
				}
				ready := make(chan struct{}, 1)
				wruntime.EventsOnce(ctx, EventReady, func(...any) { ready <- struct{}{} })
				go func() {
					select {
					case <-ready:
					case <-time.After(timeout):
						smokeErr = errors.New("smoke test: interface not ready")
					}
					wruntime.Quit(ctx)
				}()
			}
		},
		OnShutdown: func(context.Context) { a.Shutdown() },
		Bind:       []any{a},
		Windows: &windows.Options{
			Theme:               windows.SystemDefault,
			WebviewUserDataPath: webviewDataDir(),
		},
	})
	if err != nil {
		return err
	}
	return smokeErr
}

// webviewDataDir place le cache de WebView2 dans le cache utilisateur, et
// non à côté de l'exe (support éventuellement en lecture seule).
func webviewDataDir() string {
	if c, err := os.UserCacheDir(); err == nil {
		d := filepath.Join(c, "Jalon", "WebView2")
		if os.MkdirAll(d, 0o755) == nil {
			return d
		}
	}
	return filepath.Join(os.TempDir(), "jalon-webview2")
}

// shell implémente Shell avec le runtime Wails et l'API Windows.
type shell struct{ ctx context.Context }

func (s *shell) Emit(event string, data any) {
	if s.ctx != nil {
		wruntime.EventsEmit(s.ctx, event, data)
	}
}

func (s *shell) SaveFile(title, name, pattern string) (string, error) {
	if s.ctx == nil {
		return "", ErrNoShell
	}
	return wruntime.SaveFileDialog(s.ctx, wruntime.SaveDialogOptions{
		Title: title, DefaultFilename: name,
		Filters: []wruntime.FileFilter{{DisplayName: pattern, Pattern: pattern}},
	})
}

// Open passe par ShellExecute : le rapport HTML s'ouvre dans le navigateur
// par défaut (la WebView refuse file://), un dossier dans l'Explorateur.
func (s *shell) Open(path string) error {
	v, err := syscall.UTF16PtrFromString("open")
	if err != nil {
		return err
	}
	f, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return xwindows.ShellExecute(0, v, f, nil, nil, xwindows.SW_SHOWNORMAL)
}
