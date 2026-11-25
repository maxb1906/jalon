# CLAUDE.md — Jalon

**Le document de référence du projet est [docs/STRUCTURE.md](docs/STRUCTURE.md).** Lis-le avant toute tâche : il fixe les décisions (§ 0), le périmètre (§ 2 à 4), l'architecture (§ 5) et l'ordre des jalons (§ 6). En cas de doute, c'est lui qui tranche ; si un choix doit s'en écarter, demande d'abord.

## Suivi obligatoire dans docs/STRUCTURE.md

À la fin de chaque jalon :

1. **Coche le jalon terminé** dans le § 6 (`[ ]` → `[x]`).
2. **Complète le « Journal des décisions »** en fin de fichier : une ligne datée (`- **AAAA-MM-JJ** — …`) par décision prise ou écart par rapport au cadrage (versions retenues, bibliothèques ajoutées, limites découvertes…).
3. Mets à jour le statut en tête du fichier si besoin (il doit toujours refléter les tags publiés).

Ne réalise qu'un jalon à la fois, avec **un commit par jalon**, et arrête-toi à la fin du jalon demandé ; chaque jalon doit se terminer par un binaire Windows testable (`make windows`).

## Conventions

- Go installé dans `/usr/local/go` (binaire officiel go.dev, pas apt) ; `export PATH=$PATH:/usr/local/go/bin` si `go` n'est pas trouvé.
- Module : `github.com/maxb1906/jalon`. Pas de CGO (`CGO_ENABLED=0`), dépendances pures Go uniquement, **publiées depuis au moins 2 semaines** (sinon épingler une version plus ancienne).
- Code propre à un OS dans des fichiers `_windows.go` / `_linux.go` / `_darwin.go` (ou contraintes `//go:build`).
- **Lecture seule** : aucune authentification, aucune modification du poste ; chaque sonde s'arrête à la négociation du protocole. Seul `jalon-data/` est écrit, à côté de l'exe.
- **Aucune chaîne utilisateur en dur** : toute chaîne passe par `internal/i18n` et des clés présentes dans `assets/i18n/fr.json` **et** `en.json` (le test `TestEmbeddedCatalogsAreComplete` échoue sinon). Variables positionnelles `{1}`, `{2}`…
- `internal/i18n/bundle.go` est le socle commun à Arpent et Aplomb : ne le modifie pas seul, reporte toute évolution dans les trois dépôts. Même chose pour la palette `:root` du rapport.
- Tests unitaires pour chaque probe et chaque règle de verdict.
- Avant de pousser : `make fmt-check vet test build-all`.
- Ne jamais lancer de diagnostic vers des hôtes tiers depuis la devbox Oracle en dehors des tests `-tags live` ; tests réseau contre `127.0.0.1`.
