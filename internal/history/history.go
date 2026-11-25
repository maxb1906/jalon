// Package history enregistre chaque diagnostic en JSON localement (dossier
// jalon-data/historique/ à côté de l'exécutable, voir internal/config) et
// compare au diagnostic précédent. Rien n'est jamais envoyé sur le réseau.
package history

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
	"github.com/maxb1906/jalon/internal/model"
)

// Entry est un diagnostic enregistré.
type Entry struct {
	ID        string              `json:"id"`
	Time      time.Time           `json:"time"`
	TargetKey string              `json:"target_key"`
	Raw       string              `json:"raw"`
	Network   string              `json:"network"`
	Version   string              `json:"version"`
	Env       *model.EnvResult    `json:"env,omitempty"`
	Report    *model.TargetReport `json:"report"`
}

// Meta est le résumé d'une entrée pour les listes.
type Meta struct {
	ID       string       `json:"id"`
	Time     time.Time    `json:"time"`
	Raw      string       `json:"raw"`
	Target   string       `json:"target_key"`
	Network  string       `json:"network"`
	Status   model.Status `json:"status"`
	Headline i18n.Msg     `json:"headline"`
}

// Store est un dossier d'historique.
type Store struct{ Dir string }

// Open ouvre (et crée) un dossier d'historique.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("history: dossier non indiqué")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}

// NetworkKey identifie le réseau local : passerelle + IP publique estimée
// (pour distinguer « au bureau » et « à la maison »).
func NetworkKey(env *model.EnvResult) string {
	if env == nil {
		return ""
	}
	gw := "-"
	if len(env.Gateways) > 0 {
		gw = env.Gateways[0]
	}
	pub := env.PublicIP
	if pub == "" {
		pub = "-"
	}
	return gw + "|" + pub
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	return strings.Trim(b.String(), "-")
}

// Save enregistre le diagnostic d'une cible et renvoie son identifiant.
func (s *Store) Save(env *model.EnvResult, tr *model.TargetReport) (string, error) {
	rnd := make([]byte, 2)
	_, _ = rand.Read(rnd)
	id := tr.Started.Format("20060102-150405") + "-" + slug(tr.Target.Host+"-"+tr.Target.Proto) + "-" + hex.EncodeToString(rnd)
	e := Entry{ID: id, Time: tr.Started, TargetKey: tr.Target.Key(), Raw: tr.Target.Raw, Network: NetworkKey(env),
		Version: model.Version, Env: env, Report: tr}
	b, err := json.MarshalIndent(e, "", " ")
	if err != nil {
		return "", err
	}
	tmp := filepath.Join(s.Dir, id+".json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return "", err
	}
	return id, os.Rename(tmp, filepath.Join(s.Dir, id+".json"))
}

// Load charge une entrée par identifiant (préfixe accepté s'il est unique).
func (s *Store) Load(id string) (*Entry, error) {
	id = strings.TrimSuffix(filepath.Base(id), ".json")
	p := filepath.Join(s.Dir, id+".json")
	if _, err := os.Stat(p); err != nil {
		var found []string
		for _, f := range s.files() {
			if strings.HasPrefix(f, id) {
				found = append(found, f)
			}
		}
		if len(found) != 1 {
			return nil, fmt.Errorf("diagnostic %q introuvable (%d correspondance(s))", id, len(found))
		}
		p = filepath.Join(s.Dir, found[0]+".json")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, err
	}
	if e.Report == nil {
		return nil, errors.New("entrée sans rapport")
	}
	return &e, nil
}

func (s *Store) files() []string {
	des, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, d := range des {
		if n := d.Name(); !d.IsDir() && strings.HasSuffix(n, ".json") {
			out = append(out, strings.TrimSuffix(n, ".json"))
		}
	}
	sort.Strings(out)
	return out
}

// List renvoie les entrées, la plus récente en premier ; filter restreint
// aux cibles dont la saisie ou la clé contient la chaîne.
func (s *Store) List(filter string) []Meta {
	var out []Meta
	for _, id := range s.files() {
		e, err := s.Load(id)
		if err != nil {
			continue
		}
		if filter != "" && !strings.Contains(e.Raw, filter) && !strings.Contains(e.TargetKey, filter) {
			continue
		}
		out = append(out, Meta{ID: e.ID, Time: e.Time, Raw: e.Raw, Target: e.TargetKey, Network: e.Network,
			Status: e.Report.Verdict.Status, Headline: e.Report.Verdict.Headline})
	}
	slices.SortFunc(out, func(a, b Meta) int { return b.Time.Compare(a.Time) })
	return out
}

// Previous renvoie le dernier diagnostic de la même cible, de préférence
// sur le même réseau local.
func (s *Store) Previous(targetKey, network string, before time.Time) (*Entry, bool) {
	var best, bestSame *Meta
	metas := s.List("")
	for i := range metas {
		m := &metas[i]
		if m.Target != targetKey || !m.Time.Before(before) {
			continue
		}
		if best == nil {
			best = m
		}
		if m.Network == network && bestSame == nil {
			bestSame = m
		}
	}
	pick, same := best, false
	if bestSame != nil {
		pick, same = bestSame, true
	}
	if pick == nil {
		return nil, false
	}
	e, err := s.Load(pick.ID)
	if err != nil {
		return nil, false
	}
	return e, same
}

// Purge supprime les entrées plus anciennes que la durée donnée.
func (s *Store) Purge(olderThan time.Duration) (int, error) {
	limit := time.Now().Add(-olderThan)
	n := 0
	for _, m := range s.List("") {
		if m.Time.Before(limit) {
			if err := os.Remove(filepath.Join(s.Dir, m.ID+".json")); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// ---------- Comparaison ----------

func ch(kind string, sev model.Status, key string, args ...any) model.Change {
	return model.Change{Kind: kind, Severity: sev, Msg: i18n.M(key, args...)}
}

func dnsIPs(r *model.TargetReport) []string {
	if r.DNS == nil {
		return nil
	}
	ips := append(append([]string{}, r.DNS.IPv4...), r.DNS.IPv6...)
	slices.Sort(ips)
	return ips
}

func overlap(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

func shortIPs(l []string) string {
	if len(l) > 3 {
		return strings.Join(l[:3], ", ") + fmt.Sprintf(" (+%d)", len(l)-3)
	}
	if len(l) == 0 {
		return "-"
	}
	return strings.Join(l, ", ")
}

func pathAddrs(r *model.TargetReport) []string {
	for _, mode := range []string{"icmp", "tcp"} {
		if t := r.Trace(mode); t != nil && t.Available {
			var out []string
			for _, h := range t.Hops {
				if h.Addr != "" {
					out = append(out, h.Addr)
				}
			}
			return out
		}
	}
	return nil
}

func connectMs(r *model.TargetReport) float64 {
	for _, fam := range []string{"ipv4", "ipv6"} {
		if t := r.TCPFamily(fam); t != nil && t.Outcome == "connected" {
			return t.RTTMs
		}
	}
	return 0
}

var layerNames = map[string]string{"dns": "col.dns", "tcp": "col.tcp", "tls": "col.tls", "app": "col.app", "trace": "col.trace"}

// Compare liste les changements entre deux diagnostics d'une même cible.
func Compare(prev, cur *model.TargetReport) []model.Change {
	var out []model.Change
	// Couches passées de OK à échec (ou rétablies).
	pl, cl := prev.LayerStatus(), cur.LayerStatus()
	for _, c := range []string{"dns", "tcp", "tls", "app", "trace"} {
		p, n := pl[c], cl[c]
		if p == n || p == model.Skipped || n == model.Skipped {
			continue
		}
		name := i18n.M(layerNames[c])
		switch {
		case n == model.Fail:
			out = append(out, model.Change{Kind: "layer", Severity: model.Fail, Msg: i18n.Msg{Key: "chg.layer_fail", Args: []string{"@" + name.Key, "@status." + string(p)}}})
		case p == model.Fail || (p == model.Warn && n == model.OK):
			out = append(out, model.Change{Kind: "layer", Severity: model.OK, Msg: i18n.Msg{Key: "chg.layer_fixed", Args: []string{"@" + name.Key, "@status." + string(p), "@status." + string(n)}}})
		case n == model.Warn && p == model.OK:
			out = append(out, model.Change{Kind: "layer", Severity: model.Warn, Msg: i18n.Msg{Key: "chg.layer_warn", Args: []string{"@" + name.Key}}})
		}
	}
	// Adresses résolues.
	if a, b := dnsIPs(prev), dnsIPs(cur); len(a) > 0 && len(b) > 0 && !slices.Equal(a, b) {
		if !overlap(a, b) {
			out = append(out, ch("ips", model.Info, "chg.ips", shortIPs(a), shortIPs(b)))
		} else {
			out = append(out, ch("ips", model.Info, "chg.ips_partial", shortIPs(b)))
		}
	}
	// Certificat.
	if a, b := prev.TLS.LeafSHA256(), cur.TLS.LeafSHA256(); a != "" && b != "" && a != b {
		exp := cur.TLS.Chain[0].NotAfter.Format("2006-01-02")
		out = append(out, ch("cert", model.Info, "chg.cert", cur.TLS.Chain[0].Issuer, exp))
	}
	if prev.TLS != nil && cur.TLS != nil && !prev.TLS.Intercepted && cur.TLS.Intercepted {
		out = append(out, ch("cert", model.Warn, "chg.intercepted", cur.TLS.InterceptIssuer))
	}
	// Chemin réseau.
	if a, b := pathAddrs(prev), pathAddrs(cur); len(a) >= 2 && len(b) >= 2 {
		set := map[string]bool{}
		for _, x := range a {
			set[x] = true
		}
		inter := 0
		uni := len(set)
		seen := map[string]bool{}
		for _, x := range b {
			if seen[x] {
				continue
			}
			seen[x] = true
			if set[x] {
				inter++
			} else {
				uni++
			}
		}
		if float64(inter)/float64(uni) < 0.6 {
			out = append(out, ch("path", model.Info, "chg.path", len(a), len(b)))
		}
	}
	// Latence.
	if a, b := connectMs(prev), connectMs(cur); a > 0 && b > 0 && b > a*1.5 && b-a > 20 {
		out = append(out, ch("latency", model.Warn, "chg.latency_tcp", fmt.Sprintf("%.1f", a), fmt.Sprintf("%.1f", b)))
	}
	if prev.HTTP != nil && cur.HTTP != nil {
		a, b := prev.HTTP.Timings.TotalMs, cur.HTTP.Timings.TotalMs
		if a > 0 && b > 0 && b > a*1.5 && b-a > 100 {
			out = append(out, ch("latency", model.Warn, "chg.latency_http", fmt.Sprintf("%.0f", a), fmt.Sprintf("%.0f", b)))
		}
	}
	if prev.Verdict.Status != cur.Verdict.Status && len(out) == 0 {
		out = append(out, ch("verdict", cur.Verdict.Status, "chg.verdict", "@status."+string(prev.Verdict.Status), "@status."+string(cur.Verdict.Status)))
	}
	return out
}
