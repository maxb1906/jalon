// Package probe contient les sondes de la cascade : environnement, DNS,
// TCP, TLS, HTTP, HTTP/3, chemin réseau, portail captif et proxy.
//
// Toutes les sondes sont en lecture seule : elles observent, ne s'authentifient
// jamais et ne modifient rien, ni sur le poste ni sur les serveurs testés.
package probe

import (
	"context"
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

// Config regroupe les paramètres communs aux sondes.
type Config struct {
	Timeout     time.Duration // délai par étape
	Env         *model.EnvResult
	TraceProbes int
	MaxHops     int
	NoRDNS      bool
	ASN         bool
	ForceH3     bool
	// PublicResolvers : résolveurs publics comparés au DNS système.
	PublicResolvers []string
}

// DefaultConfig renvoie la configuration par défaut.
func DefaultConfig() Config {
	return Config{
		Timeout:         5 * time.Second,
		TraceProbes:     5,
		MaxHops:         30,
		PublicResolvers: []string{"1.1.1.1", "8.8.8.8"},
	}
}

// UserAgent envoyé dans les requêtes HTTP.
func UserAgent() string { return "Jalon/" + model.Version + " (+https://github.com/maxb1906/jalon)" }

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return 5 * time.Second
	}
	return c.Timeout
}

func (c Config) priv() model.Privileges {
	if c.Env == nil {
		return model.Privileges{}
	}
	return c.Env.Priv
}

// stepCtx dérive un contexte borné par le délai d'étape.
func (c Config) stepCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout())
}

func msg(key string, args ...any) i18n.Msg { return i18n.M(key, args...) }
