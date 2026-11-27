// Package model définit les types partagés entre le moteur, les sondes,
// les règles de verdict, l'historique et les rapports.
package model

import (
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
)

// Version de l'outil (remplacée au build via -ldflags).
var Version = "1.1.0"

// Status est l'état d'une étape.
type Status string

const (
	OK      Status = "ok"
	Info    Status = "info"
	Warn    Status = "warn"
	Fail    Status = "fail"
	Skipped Status = "skipped"
)

// Rank ordonne les statuts par gravité.
func (s Status) Rank() int {
	switch s {
	case OK:
		return 1
	case Info:
		return 2
	case Warn:
		return 3
	case Fail:
		return 4
	}
	return 0
}

// Worst renvoie le statut le plus grave.
func Worst(ss ...Status) Status {
	w := Skipped
	for _, s := range ss {
		if s.Rank() > w.Rank() {
			w = s
		}
	}
	return w
}

// Note est un constat secondaire au sein d'une étape.
type Note struct {
	Status Status   `json:"status"`
	Msg    i18n.Msg `json:"msg"`
}

// Base est l'en-tête commun à tous les résultats d'étape.
type Base struct {
	Status     Status   `json:"status"`
	Summary    i18n.Msg `json:"summary"`
	Notes      []Note   `json:"notes,omitempty"`
	DurationMs float64  `json:"duration_ms"`
}

// AddNote ajoute un constat.
func (b *Base) AddNote(s Status, key string, args ...any) {
	b.Notes = append(b.Notes, Note{Status: s, Msg: i18n.M(key, args...)})
}

// Set fixe statut et résumé.
func (b *Base) Set(s Status, key string, args ...any) {
	b.Status = s
	b.Summary = i18n.M(key, args...)
}

// Skip marque l'étape comme non exécutée avec sa raison.
func (b *Base) Skip(key string, args ...any) { b.Set(Skipped, key, args...) }

// Elapsed enregistre la durée depuis start.
func (b *Base) Elapsed(start time.Time) { b.DurationMs = Ms(time.Since(start)) }

// Header renvoie l'en-tête (pour les interfaces génériques).
func (b *Base) Header() *Base { return b }

// Ms convertit une durée en millisecondes arrondies au centième.
func Ms(d time.Duration) float64 {
	return float64(d.Round(10*time.Microsecond)) / float64(time.Millisecond)
}

// KV est une paire libellé (clé i18n) / valeur affichable.
type KV struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Step est la vue générique et ordonnée d'une étape, pour l'affichage.
type Step struct {
	ID    string `json:"id"`
	Layer string `json:"layer"` // clé i18n du nom de couche
	*Base
}
