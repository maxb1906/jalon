# Jalon

**Français** · [English](README.en.md)

[![CI](https://github.com/maxb1906/jalon/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/jalon/actions/workflows/ci.yml)
[![Licence : GPL-3.0](https://img.shields.io/badge/licence-GPL--3.0-blue.svg)](LICENSE)

**Diagnostic de connectivité et traceroute applicatif, couche par couche.** Un seul exécutable portable, sans installation : on lui donne une ou plusieurs cibles (`https://exemple.be`, `smtp://mail.exemple.be`, `10.0.0.5:3389`…) et il déroule une cascade de tests jusqu'à dire **où ça casse**, en langage support.

Même famille qu'[Arpent](https://github.com/maxb1906/arpent) (audit réseau) et [Aplomb](https://github.com/maxb1906/aplomb) (audit Windows) : exe portable, lecture seule, rapports exportables.

## Ce que Jalon teste

1. **Environnement local** : interface, passerelle (ping), MTU, DNS configurés, proxy (variables, WinINet/WinHTTP, macOS, PAC/WPAD), droits disponibles
2. **DNS comparé** : résolveur système / 1.1.1.1 / 8.8.8.8, interception DNS (UDP 53 vs DoH, `whoami.cloudflare`, `o-o.myaddr.l.google.com`), NXDOMAIN détourné, DNSSEC, MX/SRV
3. **TCP** IPv4 et IPv6 séparés : refus (RST) / filtré (timeout) / injoignable, « IPv6 annoncé mais cassé »
4. **TLS** : version, suite, ALPN, SNI, chaîne, expiration, nom d'hôte, auto-signé, intermédiaire manquant, algorithmes faibles, OCSP stapling, **double validation** magasin système + bundle Mozilla embarqué → détection d'**interception TLS** (Zscaler, Fortinet, Kaspersky…)
5. **HTTP/1.1 et HTTP/2** (temps DNS / TCP / TLS / TTFB / total, redirections, en-têtes notables), **HTTP/3** via Alt-Svc puis QUIC
6. **Sondes par protocole** : SMTP, IMAP, POP3 (STARTTLS ou TLS direct), SSH (KEXINIT, algorithmes obsolètes, empreinte de clé d'hôte), RDP (X.224, NLA), LDAP (StartTLS, LDAPS, RootDSE anonyme), FTP (FEAT, AUTH TLS), bannière générique
7. **Chemin réseau** façon MTR : ICMP et **TCP SYN par saut** (si droits), perte, latence, gigue, sauts muets, boucles, perte propagée vs isolée, comparaison ICMP / TCP
8. **Portail captif** (Google, Microsoft, Apple) et heuristiques de **proxy transparent** (en-têtes, adresses non routables qui répondent, délai TCP vs ICMP, TTL du SYN-ACK)

En sortie : un **verdict** en tête (« Le DNS local renvoie une IP différente des résolveurs publics → filtrage probable »), une piste d'action, le détail de chaque étape, la **comparaison avec le diagnostic précédent** et un **résumé prêt à coller dans un ticket**.

> **Lecture seule.** Jalon observe, ne modifie rien sur le poste, ne s'authentifie jamais et s'arrête à la négociation de chaque protocole. Aucun service externe propre à Jalon : rien n'est envoyé ailleurs que vers les cibles et les résolveurs/sondes publics cités ci-dessus.

## Démarrage

1. Téléchargez l'archive de votre plateforme depuis les [Releases](https://github.com/maxb1906/jalon/releases) : `jalon_<version>_windows_amd64.zip` (ou `windows_arm64`, `linux_*`, `darwin_*` en `.tar.gz`), et décompressez-la, par exemple sur une clé USB.
2. **Sous Windows, double-cliquez sur `jalon.exe`** : l'interface web s'ouvre dans le navigateur (la fenêtre console doit rester ouverte pendant l'utilisation).
3. Saisissez une ou plusieurs cibles, suivez la cascade en direct, puis exportez le rapport.

Toutes les données sont dans le dossier `jalon-data/`, **à côté de l'exécutable** : préférences (`config.yaml`), historique (`historique/`) et rapports (`rapports/`). Rien n'est écrit dans le registre ni dans `%APPDATA%`. Si ce dossier n'est pas inscriptible (clé en lecture seule), Jalon le signale et utilise le dossier temporaire du système.

> **Windows bloque l'exe** : l'exécutable n'est pas encore signé. Selon le PC :
> - **SmartScreen** (« Windows a protégé votre ordinateur ») : cliquez sur « Informations complémentaires » puis « Exécuter quand même ».
> - **Contrôle intelligent des applications** (Windows 11) : l'exe est bloqué **sans bouton pour passer outre** ni exception par application. La seule solution est de le désactiver (Sécurité Windows → *Contrôle des applications et du navigateur* → *Paramètres du Contrôle intelligent des applications* → *Désactivé*) ; depuis la mise à jour d'avril 2026 de Windows 11, on peut le réactiver ensuite sans réinstaller Windows. Sur le poste d'un client, ne le désactivez qu'avec son accord.
> - Un outil qui ouvre des sockets ICMP « raw » peut aussi être signalé par certains **antivirus**.
>
> Vérifiez l'empreinte avec le fichier `SHA256SUMS` de la release. La signature de code (SignPath Foundation, après celle d'Arpent) lèvera ces blocages.

## Ligne de commande

Ouvrez un terminal (PowerShell ou `cmd`) dans le dossier de l'exe :

```
jalon https://exemple.be
jalon smtp://mail.exemple.be imaps://mail.exemple.be 10.0.0.5:3389
jalon -f cibles.txt --format html,md        # une cible par ligne, # = commentaire
jalon tui https://exemple.be                # interface terminal : cascade + MTR live
jalon web                                   # interface web locale (127.0.0.1, jeton)
jalon --json exemple.be > rapport.json      # JSON sur la sortie standard
jalon --ticket exemple.be                   # uniquement le résumé ticket
jalon --format html --report-lang en exemple.be
jalon history                               # historique ; « jalon history purge 30d »
jalon diff <id1> <id2>                      # comparer deux diagnostics
jalon version
```

| Option | Rôle |
|---|---|
| `--trace-mode icmp\|tcp\|auto` | mode du traceroute (auto : ICMP, et TCP SYN si les droits le permettent) |
| `--no-trace` | pas de traceroute |
| `--ipv4` / `--ipv6` (`-4` / `-6`) | une seule famille d'adresses |
| `--proto smtp` | forcer le protocole (http, https, smtp, imap, pop3, ssh, rdp, ldap, ftp, banner) |
| `--timeout 5s` | délai par étape |
| `--format html,md,json,ticket` | rapports à écrire, dans `jalon-data/rapports/` (`--out <dossier>` pour un autre dossier, `-o <fichier>` pour un seul format) |
| `--report-lang fr\|en` | langue des rapports (défaut : `config.yaml`, sinon celle de l'outil) |
| `--json`, `--ticket` | ce qui est affiché sur la sortie standard |
| `--lang fr\|en` | langue de l'outil (défaut : langue du système ; variable `JALON_LANG`) |
| `--data <dossier>` | dossier de données (variable `JALON_DATA`) |
| `--parallel 4` | cibles traitées en parallèle (les traceroutes restent sérialisés, sauf `--parallel-trace`) |
| `--h3` | tenter QUIC même sans annonce Alt-Svc |
| `--asn`, `--no-rdns`, `--probes 5`, `--max-hops 30` | options du traceroute |
| `--no-history`, `--history-dir` | historique |
| `-v` | afficher aussi les informations détaillées |

Les anciennes formes `--web`, `--tui` et `--report <format>` restent acceptées.

Le protocole est déduit du schéma (`smtp://`, `submission://`, `smtps://`, `imaps://`, `pop3s://`, `ssh://`, `rdp://`, `ldap://`, `ldaps://`, `ftp://`, `tcp://`, `tls://`) ou du port standard. Une cible sans schéma ni port est testée en HTTPS. Une cible qui s'appellerait `web` ou `tui` s'écrit `https://web` ou `web:443`.

### Codes de sortie

| Code | Signification |
|---|---|
| `0` | diagnostic OK |
| `1` | avertissement |
| `2` | échec du diagnostic |
| `3` | erreur d'utilisation ou d'exécution de Jalon (option invalide, fichier de cibles illisible, rapport impossible à écrire…) |

Un script peut ainsi distinguer « la cible est cassée » (`2`) de « la commande est fausse » (`3`).

### Droits et traceroute

| Système | ICMP | TCP SYN par saut |
|---|---|---|
| Windows | toujours (`IcmpSendEcho`, IPv4) | administrateur (socket ICMP raw, sans Npcap) |
| Linux | root, `CAP_NET_RAW`, ou ping non privilégié (`net.ipv4.ping_group_range`) | root ou `CAP_NET_RAW` |
| macOS | toujours (socket ICMP datagramme ; root recommandé) | root |

Sans les droits, le mode est affiché « non disponible » avec la raison, jamais d'échec silencieux. Sous Linux, `sudo setcap cap_net_raw+ep ./jalon` donne tous les modes sans root.

## Configuration

`jalon-data/config.yaml` (créé avec le dossier de données) a la même forme que dans Arpent et Aplomb :

```yaml
technician: "Nom"            # page de garde des rapports
lang: ""                     # langue de l'outil (vide : système)
report_lang: ""              # langue des rapports (vide : celle de l'outil)
issuer:                      # émetteur des rapports
  name: "Nom"
  company: "Ma société"
  contact: "rue de l'Exemple 1, 4000 Liège · contact@exemple.be"
  legal: "TVA BE0123.456.789"   # pied du rapport
  color: "#1f5f8b"              # couleur principale du rapport
  logo: logo.png                # relatif à jalon-data/
```

## Historique

Chaque diagnostic est enregistré en JSON dans `jalon-data/historique/`. Il est indexé par cible et par réseau local (passerelle + IP publique estimée), et comparé automatiquement au précédent : IP résolues, certificat, chemin réseau, latence, couche passée de OK à échec. Rien n'est jamais envoyé sur le réseau. L'ancien dossier `jalon-history/` des versions 1.0.x est déplacé automatiquement ; un historique resté dans `%APPDATA%\jalon\history` est à copier à la main dans `jalon-data\historique`.

## Interface web

`jalon web` écoute uniquement sur `127.0.0.1`, sur un port aléatoire, avec un jeton dans l'URL et un contrôle de l'en-tête `Host` (hôte et port, contre le DNS rebinding). Saisie des cibles, suivi en direct (Server-Sent Events), historique, comparaison et export (HTML, Markdown, JSON, ticket). Tous les fichiers sont embarqués : aucun CDN.

## Compilation

Prérequis : [Go](https://go.dev/dl/) (version de `go.mod`). Aucun CGO : la cross-compilation fonctionne depuis n'importe quel système.

```sh
make test        # tests (avec détecteur de courses)
make windows     # dist/jalon-windows-amd64.exe
make build-all   # windows, linux, darwin × amd64, arm64
make all         # format, vet (Linux, Windows, macOS), tests, binaires
go test -tags live -run TestLive -v ./internal/probe/   # tests contre le vrai réseau
```

La CI lance aussi l'exe sur Windows (diagnostic sur `127.0.0.1`, rapports, interface web). Les versions sont publiées par GitHub Actions + GoReleaser à chaque tag `vX.Y.Z`.

## Contribuer

- Traductions : `assets/i18n/fr.json` et `en.json` (mêmes clés et mêmes variables `{1}`, `{2}`…, vérifié par les tests).
- Architecture : `internal/engine` (cascade + bus d'événements), `internal/probe` (env, dns, tcp, tls, http, http3, trace, captive, proxy), `internal/probe/proto` (smtp, imap, pop3, ssh, rdp, ldap, ftp, banner), `internal/verdict` (règles testées une à une), `internal/history`, `internal/report`, `internal/config`, `internal/ui/tui`, `internal/ui/web`, `internal/i18n`.
- Cadrage et décisions : [docs/STRUCTURE.md](docs/STRUCTURE.md).

## Licence

[GPL-3.0](LICENSE).
