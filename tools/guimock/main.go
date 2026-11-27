// Commande guimock : prépare le mode démonstration du frontend
// (« cd frontend && npm run dev », dans un navigateur, sans Wails) en
// écrivant les catalogues de traduction dans frontend/src/lib/mock.
//
//	go run ./tools/guimock
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/ui/session"
)

func main() {
	dir := filepath.Join("frontend", "src", "lib", "mock")
	for _, l := range []i18n.Lang{i18n.FR, i18n.EN} {
		b, err := json.MarshalIndent(session.Catalog(l), "", " ")
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "catalog."+string(l)+".json"), b, 0o644)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fmt.Println("catalogues écrits dans", dir)
}
