package main

import (
	"io/fs"

	"github.com/maxb1906/jalon/frontend"
)

// guiAssets renvoie l'interface graphique embarquée (Windows uniquement).
func guiAssets() fs.FS { return frontend.Dist() }
