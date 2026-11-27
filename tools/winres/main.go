// Commande winres : génère les ressources Windows de l'exe (icône,
// manifeste, informations de version) dans cmd/jalon/rsrc_windows_<arch>.syso,
// que « go build » lie automatiquement.
//
//	go run ./tools/winres -version 1.1.0
//
// Le manifeste déclare asInvoker (Jalon fonctionne sans droits ; le
// traceroute TCP SYN demande l'administrateur), la prise en charge du DPI par
// écran (fenêtre nette) et les Common Controls v6 (boîtes de dialogue).
package main

import (
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func main() {
	ver := flag.String("version", "dev", "version de l'exe (ex. 1.1.0 ou v1.1.0-3-gabc)")
	out := flag.String("out", filepath.Join("cmd", "jalon"), "dossier des fichiers .syso")
	preview := flag.String("png", "", "écrit aussi l'icône 256×256 dans ce fichier PNG (aperçu)")
	flag.Parse()
	if *preview != "" {
		if err := writePNG(*preview, drawIcon(256)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := run(*ver, *out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ver, out string) error {
	rs := winres.ResourceSet{}
	var imgs []image.Image
	for _, s := range []int{16, 20, 24, 32, 40, 48, 64, 128, 256} {
		imgs = append(imgs, drawIcon(s))
	}
	icon, err := winres.NewIconFromImages(imgs)
	if err != nil {
		return err
	}
	if err := rs.SetIcon(winres.Name("APPICON"), icon); err != nil {
		return err
	}
	rs.SetManifest(winres.AppManifest{
		Identity:            winres.AssemblyIdentity{Name: "Jalon"},
		Description:         "Jalon",
		Compatibility:       winres.Win10AndAbove,
		ExecutionLevel:      winres.AsInvoker,
		DPIAwareness:        winres.DPIPerMonitorV2,
		UseCommonControlsV6: true,
		LongPathAware:       true,
	})
	num := numeric(ver)
	vi := version.Info{}
	vi.SetFileVersion(num)
	vi.SetProductVersion(num)
	for k, v := range map[string]string{
		version.ProductName:      "Jalon",
		version.FileDescription:  "Jalon - layer-by-layer connectivity diagnosis (read-only)",
		version.CompanyName:      "maxb1906",
		version.LegalCopyright:   "GPL-3.0-or-later",
		version.OriginalFilename: "jalon.exe",
		version.InternalName:     "jalon",
		version.ProductVersion:   ver,
		version.FileVersion:      ver,
	} {
		if err := vi.Set(0, k, v); err != nil {
			return err
		}
	}
	rs.SetVersionInfo(vi)
	for name, arch := range map[string]winres.Arch{"amd64": winres.ArchAMD64, "arm64": winres.ArchARM64} {
		p := filepath.Join(out, "rsrc_windows_"+name+".syso")
		f, err := os.Create(p)
		if err != nil {
			return err
		}
		if err := rs.WriteObject(f, arch); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func writePNG(path string, img image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

var reVersion = regexp.MustCompile(`^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?`)

// numeric extrait « 1.1.0.0 » d'une version de type v1.1.0-3-gabc (0.0.0.0 si absente).
func numeric(v string) string {
	m := reVersion.FindStringSubmatch(v)
	parts := [3]int{}
	for i := 0; m != nil && i < 3; i++ {
		parts[i], _ = strconv.Atoi(m[i+1])
	}
	return fmt.Sprintf("%d.%d.%d.0", parts[0], parts[1], parts[2])
}

type rgba [4]float64

var (
	blue  = rgba{0x24, 0x53, 0xc7, 255}
	white = rgba{255, 255, 255, 255}
	red   = rgba{0xd2, 0x3c, 0x2a, 255}
	none  = rgba{}
)

// drawIcon dessine le jalon d'arpenteur (mêmes formes que
// frontend/src/components/Logo.svelte, repère 32×32), anticrénelé par
// suréchantillonnage 4×4.
func drawIcon(size int) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var acc rgba
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					u := (float64(x) + (float64(sx)+.5)/ss) * 32 / float64(size)
					v := (float64(y) + (float64(sy)+.5)/ss) * 32 / float64(size)
					c := shade(u, v)
					a := c[3] / 255
					for i := 0; i < 3; i++ {
						acc[i] += c[i] * a
					}
					acc[3] += a
				}
			}
			if acc[3] == 0 {
				continue
			}
			c := func(i int) uint8 { return uint8(math.Round(acc[i] / acc[3])) }
			img.SetNRGBA(x, y, color.NRGBA{c(0), c(1), c(2), uint8(math.Round(acc[3] / (ss * ss) * 255))})
		}
	}
	return img
}

func shade(u, v float64) rgba {
	if !inRoundRect(u, v, 2, 2, 30, 30, 7) {
		return none
	}
	// Piquet rayé (13.6→18.4, 5.5→22.5), bandes rouges en haut et au milieu.
	if u >= 13.6 && u <= 18.4 && v >= 5.5 && v <= 22.5 {
		if v <= 9.7 || (v >= 13.9 && v <= 18.1) {
			return red
		}
		return white
	}
	// Pointe plantée dans le sol.
	if inPoly(u, v, [][2]float64{{13.6, 22.5}, {18.4, 22.5}, {16, 26}}) {
		return white
	}
	// Ligne de sol, blanc à 55 %.
	if v >= 24.7 && v <= 26.3 && u >= 7 && u <= 25 {
		const a = .55
		return rgba{blue[0]*(1-a) + 255*a, blue[1]*(1-a) + 255*a, blue[2]*(1-a) + 255*a, 255}
	}
	return blue
}

func inRoundRect(u, v, x0, y0, x1, y1, r float64) bool {
	if u < x0 || u > x1 || v < y0 || v > y1 {
		return false
	}
	cx := math.Max(x0+r, math.Min(u, x1-r))
	cy := math.Max(y0+r, math.Min(v, y1-r))
	return (u-cx)*(u-cx)+(v-cy)*(v-cy) <= r*r
}

func inPoly(x, y float64, pts [][2]float64) bool {
	in := false
	for i, j := 0, len(pts)-1; i < len(pts); j, i = i, i+1 {
		if (pts[i][1] > y) != (pts[j][1] > y) && x < (pts[j][0]-pts[i][0])*(y-pts[i][1])/(pts[j][1]-pts[i][1])+pts[i][0] {
			in = !in
		}
	}
	return in
}
