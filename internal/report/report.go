// Package report produit les sorties : texte terminal, JSON, Markdown,
// HTML autonome et résumé ticket.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

// JSON écrit le rapport en JSON indenté. Les messages sont accompagnés de
// leur rendu dans la langue du rapport (champ « text »).
func JSON(w io.Writer, rep *model.Report) error {
	b, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	addText(v, rep.Lang)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// addText ajoute « text » à chaque objet {key, args}.
func addText(v any, l i18n.Lang) {
	switch x := v.(type) {
	case map[string]any:
		if k, ok := x["key"].(string); ok && len(x) <= 2 {
			var args []string
			if a, ok := x["args"].([]any); ok {
				for _, s := range a {
					args = append(args, fmt.Sprint(s))
				}
			}
			x["text"] = i18n.Msg{Key: k, Args: args}.In(l)
			return
		}
		for _, e := range x {
			addText(e, l)
		}
	case []any:
		for _, e := range x {
			addText(e, l)
		}
	}
}

// Icon renvoie le symbole d'un statut.
func Icon(s model.Status) string {
	switch s {
	case model.OK:
		return "✔"
	case model.Warn:
		return "⚠"
	case model.Fail:
		return "✖"
	case model.Info:
		return "ℹ"
	}
	return "·"
}

// StatusText renvoie le libellé d'un statut.
func StatusText(l i18n.Lang, s model.Status) string {
	if s == "" {
		s = model.Skipped
	}
	return i18n.T(l, "status."+string(s))
}

// Columns du tableau de synthèse.
var Columns = []string{"dns", "tcp", "tls", "app", "trace"}

func fmtTime(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05") }

// TargetTitle renvoie l'intitulé d'une cible.
func TargetTitle(t model.Target) string {
	return fmt.Sprintf("%s  (%s, %s:%d)", t.Raw, strings.ToUpper(t.Proto), t.Host, t.Port)
}
