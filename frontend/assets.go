// Package frontend embarque l'interface graphique compilée (frontend/dist).
//
// dist est produit par « npm run build » (scripts/build.sh le fait) ; sans
// lui, seul .gitkeep est embarqué et Jalon se replie sur l'UI web.
package frontend

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist renvoie les fichiers de l'interface, à la racine.
func Dist() fs.FS {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
