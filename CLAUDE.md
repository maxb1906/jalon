# Jalon
Le cahier des charges complet est dans `docs/Structure projet.md` : décisions (§0), périmètre, architecture, jalons de dev (§6).
- Suivre les jalons du §6 dans l'ordre et cocher chaque case dans `docs/Structure projet.md` une fois terminée.
- Go, GPL-3.0, textes FR + EN, outil strictement en lecture seule (aucune authentification, aucune modification).
- Tests unitaires pour chaque probe et chaque règle de verdict ; `go vet` et `go test ./...` doivent passer avant chaque commit.
- Cross-compilation : windows/linux/darwin × amd64/arm64, sans cgo si possible.
