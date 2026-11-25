// Package config gère le dossier de données portable (jalon-data/) et les
// préférences (config.yaml), comme Arpent et Aplomb.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	// DirName est le nom du dossier de données placé à côté de l'exécutable.
	DirName = "jalon-data"

	// HistoryDirName et ReportsDirName sont les sous-dossiers du dossier de données.
	HistoryDirName = "historique"
	ReportsDirName = "rapports"

	// LegacyHistoryDirName est l'ancien dossier d'historique (v1.0.x).
	LegacyHistoryDirName = "jalon-history"

	// EnvVar désigne le dossier de données (équivalent de --data).
	EnvVar = "JALON_DATA"
)

// Resolve calcule le dossier de données sans le créer : flag, sinon variable
// JALON_DATA, sinon jalon-data/ à côté de l'exécutable (dans le dossier
// courant pour « go run » ou « go test »). explicit indique que le dossier a
// été choisi par l'utilisateur.
func Resolve(flag string) (dir string, explicit bool, err error) {
	dir = flag
	if dir == "" {
		dir = os.Getenv(EnvVar)
	}
	explicit = dir != ""
	if dir == "" {
		dir = filepath.Join(exeDir(), DirName)
	}
	dir, err = filepath.Abs(dir)
	return dir, explicit, err
}

// DataDir renvoie le dossier de données, créé et inscriptible. Si le dossier
// par défaut (à côté de l'exe) n'est pas inscriptible, par exemple sur une clé
// en lecture seule, le dossier temporaire du système est utilisé et fallback
// vaut true : l'appelant doit avertir l'utilisateur. Un dossier choisi
// explicitement (--data, JALON_DATA) n'a pas de repli.
func DataDir(flag string) (dir string, fallback bool, err error) {
	dir, explicit, err := Resolve(flag)
	if err != nil {
		return "", false, err
	}
	if writable(dir) {
		return dir, false, nil
	}
	if explicit {
		return "", false, errors.New(dir)
	}
	tmp := filepath.Join(os.TempDir(), DirName)
	if !writable(tmp) {
		return "", false, errors.New(dir)
	}
	return tmp, true, nil
}

// HistoryDir et ReportsDir renvoient les sous-dossiers du dossier de données.
func HistoryDir(dataDir string) string { return filepath.Join(dataDir, HistoryDirName) }

// ReportsDir renvoie le dossier des rapports.
func ReportsDir(dataDir string) string { return filepath.Join(dataDir, ReportsDirName) }

// MigrateLegacyHistory déplace l'ancien dossier jalon-history/ (à côté de
// l'exe, v1.0.x) vers jalon-data/historique/ s'il n'existe pas encore.
// Renvoie l'ancien chemin si un déplacement a eu lieu.
func MigrateLegacyHistory(dataDir string) string {
	old := filepath.Join(filepath.Dir(dataDir), LegacyHistoryDirName)
	if st, err := os.Stat(old); err != nil || !st.IsDir() {
		return ""
	}
	dst := HistoryDir(dataDir)
	if _, err := os.Stat(dst); err == nil {
		return ""
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return ""
	}
	if err := os.Rename(old, dst); err != nil {
		return ""
	}
	return old
}

func exeDir() string {
	exe, err := os.Executable()
	if err == nil {
		if real, err2 := filepath.EvalSymlinks(exe); err2 == nil {
			exe = real
		}
	}
	if err != nil || isTempBuild(exe) {
		wd, _ := os.Getwd()
		return wd
	}
	return filepath.Dir(exe)
}

func isTempBuild(exe string) bool {
	s := filepath.ToSlash(exe)
	return strings.Contains(s, "/go-build") || strings.HasSuffix(s, ".test") || strings.HasSuffix(s, ".test.exe")
}

func writable(dir string) bool {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return false
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}
