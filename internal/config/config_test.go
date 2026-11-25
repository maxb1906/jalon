package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestTemplateParses(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte(Template), &c); err != nil {
		t.Fatal(err)
	}
	if !c.Issuer.IsZero() || c.Technician != "" {
		t.Errorf("modèle non vide : %+v", c)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if c, err := Load(dir); err != nil || c.Technician != "" {
		t.Fatalf("absent : %+v %v", c, err)
	}
	if err := WriteTemplate(dir); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("technician: \" Ada \"\nreport_lang: en\nissuer:\n  company: Société\n  color: \"#aa3300\"\n  logo: logo.png\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "logo.png"), []byte("\x89PNG\r\n\x1a\n"), 0o644)
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.Technician != "Ada" || c.ReportLang != "en" || c.Issuer.Company != "Société" || c.Issuer.Color != "#aa3300" {
		t.Errorf("%+v", c)
	}
	if u := c.LogoDataURI(dir); !strings.HasPrefix(u, "data:image/png;base64,") {
		t.Errorf("logo : %q", u)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("issuer:\n  color: \"red;}body{x\"\n  logo: ../secret.png\n"), 0o644)
	if c, _ = Load(dir); c.Issuer.Color != "" || c.Issuer.Logo != "" {
		t.Errorf("valeurs dangereuses acceptées : %+v", c.Issuer)
	}
	os.WriteFile(filepath.Join(dir, FileName), []byte("technician: [\n"), 0o644)
	if _, err := Load(dir); err == nil {
		t.Error("YAML invalide : erreur attendue")
	}
}

func TestDataDir(t *testing.T) {
	d := filepath.Join(t.TempDir(), "data")
	got, fb, err := DataDir(d)
	if err != nil || fb || got != d {
		t.Fatalf("%q %v %v", got, fb, err)
	}
	t.Setenv(EnvVar, d)
	if got, explicit, _ := Resolve(""); got != d || !explicit {
		t.Errorf("JALON_DATA : %q %v", got, explicit)
	}
	t.Setenv(EnvVar, "")
	if got, explicit, _ := Resolve(""); filepath.Base(got) != DirName || explicit {
		t.Errorf("défaut : %q %v", got, explicit)
	}
}

func TestMigrateLegacyHistory(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, DirName)
	old := filepath.Join(root, LegacyHistoryDirName)
	os.MkdirAll(old, 0o755)
	os.WriteFile(filepath.Join(old, "x.json"), []byte("{}"), 0o644)
	if got := MigrateLegacyHistory(data); got != old {
		t.Fatalf("migration : %q", got)
	}
	if _, err := os.Stat(filepath.Join(HistoryDir(data), "x.json")); err != nil {
		t.Error("fichier non déplacé")
	}
	if got := MigrateLegacyHistory(data); got != "" {
		t.Error("deuxième migration inattendue")
	}
}
