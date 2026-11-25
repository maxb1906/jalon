package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName est le fichier de préférences dans le dossier de données.
const FileName = "config.yaml"

// MaxLogoBytes limite la taille du logo intégré au rapport.
const MaxLogoBytes = 512 << 10

// Issuer est l'émetteur des rapports (page de garde). Même forme que dans
// Arpent et Aplomb.
type Issuer struct {
	Name    string `yaml:"name" json:"name,omitempty"`
	Company string `yaml:"company" json:"company,omitempty"`
	Contact string `yaml:"contact" json:"contact,omitempty"` // adresse, téléphone, courriel…
	Legal   string `yaml:"legal" json:"legal,omitempty"`     // mentions légales en pied de rapport
	Color   string `yaml:"color" json:"color,omitempty"`     // couleur principale, ex. #1f5f8b
	Logo    string `yaml:"logo" json:"-"`                    // image relative au dossier de données
}

// IsZero indique si aucun champ de l'émetteur n'est renseigné.
func (i Issuer) IsZero() bool { return i == Issuer{} }

// Config : préférences de l'utilisateur (jalon-data/config.yaml).
type Config struct {
	Technician string `yaml:"technician"`  // nom du technicien (page de garde)
	Lang       string `yaml:"lang"`        // langue de l'outil (vide : système)
	ReportLang string `yaml:"report_lang"` // langue des rapports (vide : celle de l'outil)
	Issuer     Issuer `yaml:"issuer"`      // émetteur des rapports
}

// Load lit dataDir/config.yaml ; un fichier absent donne une configuration vide.
func Load(dataDir string) (Config, error) {
	var c Config
	b, err := os.ReadFile(filepath.Join(dataDir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("%s : %w", FileName, err)
	}
	c.normalize()
	return c, nil
}

func (c *Config) normalize() {
	c.Technician = strings.TrimSpace(c.Technician)
	c.Lang = strings.TrimSpace(c.Lang)
	c.ReportLang = strings.TrimSpace(c.ReportLang)
	if col := strings.TrimSpace(c.Issuer.Color); col != "" && !ValidColor(col) {
		c.Issuer.Color = ""
	} else {
		c.Issuer.Color = col
	}
	// Le logo doit rester dans le dossier de données (portable).
	if l := filepath.ToSlash(c.Issuer.Logo); filepath.IsAbs(c.Issuer.Logo) || strings.HasPrefix(l, "../") || strings.Contains(l, "/../") || strings.HasPrefix(l, "/") {
		c.Issuer.Logo = ""
	}
}

// ValidColor accepte une couleur CSS #rrggbb.
func ValidColor(s string) bool {
	if len(s) != 7 || s[0] != '#' {
		return false
	}
	for _, r := range s[1:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// LogoDataURI lit le logo dans le dossier de données et le renvoie en data:
// URI ("" si absent, trop gros ou d'un type non pris en charge).
func (c Config) LogoDataURI(dataDir string) string {
	if c.Issuer.Logo == "" {
		return ""
	}
	path := filepath.Join(dataDir, filepath.FromSlash(c.Issuer.Logo))
	st, err := os.Stat(path)
	if err != nil || st.Size() > MaxLogoBytes {
		return ""
	}
	typ := mime.TypeByExtension(strings.ToLower(filepath.Ext(path)))
	if i := strings.IndexByte(typ, ';'); i >= 0 {
		typ = typ[:i]
	}
	switch typ {
	case "image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml":
	default:
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return "data:" + typ + ";base64," + base64.StdEncoding.EncodeToString(b)
}

// Template est le fichier d'exemple créé avec le dossier de données.
const Template = `# Configuration de Jalon / Jalon configuration
# Toutes les clés sont facultatives. / All keys are optional.

# Technicien affiché sur la page de garde du rapport.
technician: ""

# Langue de l'outil et des rapports : fr | en (vide : langue du système)
lang: ""
report_lang: ""

# Émetteur des rapports (page de garde et pied de page), comme dans Arpent et Aplomb.
issuer:
  name: ""
  company: ""
  contact: ""     # adresse, téléphone, courriel
  legal: ""       # mentions légales en pied de rapport
  color: ""       # couleur principale, ex. "#1f5f8b"
  logo: ""        # PNG, JPEG, GIF, WebP ou SVG, relatif à ce dossier : logo.png
`

// WriteTemplate crée config.yaml s'il n'existe pas encore.
func WriteTemplate(dataDir string) error {
	p := filepath.Join(dataDir, FileName)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(Template), 0o644)
}
