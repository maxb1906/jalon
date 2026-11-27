# Jalon

**Diagnostic de connectivité et traceroute applicatif, couche par couche.**
*Layer-by-layer connectivity diagnosis and application traceroute — [English below](#english).*

Jalon reçoit une ou plusieurs cibles (`https://exemple.be`, `smtp://mail.exemple.be`, `10.0.0.5:3389`…) et déroule une cascade de tests jusqu'à dire **où ça casse**, en langage support :

1. Environnement local : interface, passerelle (ping), MTU, DNS configurés, proxy (variables, WinINet/WinHTTP, macOS, PAC/WPAD), droits disponibles
2. DNS comparé : résolveur système / 1.1.1.1 / 8.8.8.8, interception DNS (UDP 53 vs DoH, `whoami.cloudflare`, `o-o.myaddr.l.google.com`), NXDOMAIN détourné, DNSSEC, MX/SRV
3. TCP IPv4 et IPv6 séparés : refus (RST) / filtré (timeout) / injoignable, « IPv6 annoncé mais cassé »
4. TLS : version, suite, ALPN, SNI, chaîne, expiration, nom d'hôte, auto-signé, intermédiaire manquant, algorithmes faibles, OCSP stapling, **double validation** magasin système + bundle Mozilla embarqué → détection d'**interception TLS** (Zscaler, Fortinet, Kaspersky…)
5. HTTP/1.1 et HTTP/2 (temps DNS / TCP / TLS / TTFB / total, redirections, en-têtes notables), **HTTP/3** via Alt-Svc puis QUIC
6. Sondes par protocole : SMTP, IMAP, POP3 (STARTTLS ou TLS direct), SSH (KEXINIT, algorithmes obsolètes, empreinte de clé d'hôte), RDP (X.224, NLA), LDAP (StartTLS, LDAPS, RootDSE anonyme), FTP (FEAT, AUTH TLS), bannière générique
7. Chemin réseau façon MTR : ICMP et **TCP SYN par saut** (si droits), perte, latence, gigue, sauts muets, boucles, perte propagée vs isolée, comparaison ICMP / TCP
8. Portail captif (Google, Microsoft, Apple) et heuristiques de **proxy transparent** (en-têtes, adresses non routables qui répondent, délai TCP vs ICMP, TTL du SYN-ACK)

En sortie : un **verdict** en tête (« Le DNS local renvoie une IP différente des résolveurs publics → filtrage probable »), une piste d'action, le détail de chaque étape, la **comparaison avec le diagnostic précédent** et un **résumé prêt à coller dans un ticket**.

> **Lecture seule.** Jalon observe, ne modifie rien sur le poste, ne s'authentifie jamais et s'arrête à la négociation de chaque protocole. Aucun service externe propre à Jalon : rien n'est envoyé ailleurs que vers les cibles et les résolveurs/sondes publics cités ci-dessus.

## Installation

Un seul exécutable portable, sans dépendance. Téléchargez celui de votre plateforme dans les [releases](https://github.com/maxb1906/jalon/releases) (Windows, Linux, macOS ; amd64 et arm64) ou compilez :

```sh
go build -o jalon ./cmd/jalon        # Go ≥ 1.27 (CLI, TUI, interface web)
scripts/build.sh 1.1.0               # les 6 plateformes dans dist/, sans cgo ; Node.js LTS requis pour l'interface graphique
```

## Utilisation

**Sous Windows, un double-clic sur `jalon.exe` ouvre l'interface graphique** : une fenêtre native (Wails + WebView2) avec la cascade en direct, le tableau de synthèse multi-cible, le chemin réseau live, l'historique et sa comparaison, l'aperçu du rapport, l'export (HTML, Markdown, JSON) et le résumé ticket copié en un clic. Sans le composant WebView2 (Windows Server 2016 à 2022), Jalon ouvre à la place l'interface web dans le navigateur.

Pour la ligne de commande, ouvrir un terminal (PowerShell ou `cmd`) dans le dossier de l'exe :

```sh
jalon https://exemple.be
jalon smtp://mail.exemple.be imaps://mail.exemple.be 10.0.0.5:3389
jalon -f cibles.txt --report html          # une cible par ligne, # = commentaire
jalon --gui                                # interface graphique (Windows ; ailleurs : interface web)
jalon --tui https://exemple.be             # interface terminal : cascade + MTR live
jalon --web                                # interface web locale (127.0.0.1, jeton)
jalon --json exemple.be > rapport.json
jalon --ticket exemple.be                  # uniquement le résumé ticket
jalon history                              # historique ; « jalon history purge 30d »
jalon diff <id1> <id2>                     # comparer deux diagnostics
```

| Option | Rôle |
|---|---|
| `--trace-mode icmp\|tcp\|auto` | mode du traceroute (auto : ICMP, et TCP SYN si les droits le permettent) |
| `--no-trace` | pas de traceroute |
| `--ipv4` / `--ipv6` (`-4` / `-6`) | une seule famille d'adresses |
| `--proto smtp` | forcer le protocole (http, https, smtp, imap, pop3, ssh, rdp, ldap, ftp, banner) |
| `--timeout 5s` | délai par étape |
| `--json`, `--report html\|md\|json`, `-o fichier` | sorties |
| `--lang fr\|en` | langue (défaut : langue du système ; variable `JALON_LANG`) |
| `--parallel 4` | cibles traitées en parallèle (les traceroutes restent sérialisés, sauf `--parallel-trace`) |
| `--h3` | tenter QUIC même sans annonce Alt-Svc |
| `--asn`, `--no-rdns`, `--probes 5`, `--max-hops 30` | options du traceroute |
| `--no-history`, `--history-dir` | historique |
| `-v` | afficher aussi les informations détaillées |

Le protocole est déduit du schéma (`smtp://`, `submission://`, `smtps://`, `imaps://`, `pop3s://`, `ssh://`, `rdp://`, `ldap://`, `ldaps://`, `ftp://`, `tcp://`, `tls://`) ou du port standard. Une cible sans schéma ni port est testée en HTTPS.

**Codes de sortie** : `0` OK, `1` avertissement, `2` échec — exploitables en script.

### Droits et traceroute

| Système | ICMP | TCP SYN par saut |
|---|---|---|
| Windows | toujours (`IcmpSendEcho`, IPv4) | administrateur (socket ICMP raw) |
| Linux | root, `CAP_NET_RAW`, ou ping non privilégié (`net.ipv4.ping_group_range`) | root ou `CAP_NET_RAW` |
| macOS | toujours (socket ICMP datagramme ; root recommandé) | root |

Sans les droits, le mode est affiché « non disponible » avec la raison, jamais d'échec silencieux. Sous Linux, `sudo setcap cap_net_raw+ep ./jalon` donne tous les modes sans root.

### Historique

Chaque diagnostic est enregistré en JSON dans `jalon-history/` **à côté de l'exécutable** (repli : dossier de configuration utilisateur). Il est indexé par cible et par réseau local (passerelle + IP publique estimée), et comparé automatiquement au précédent : IP résolues, certificat, chemin réseau, latence, couche passée de OK à échec. Rien n'est jamais envoyé sur le réseau.

### Interface web

`jalon --web` écoute uniquement sur `127.0.0.1`, sur un port aléatoire, avec un jeton dans l'URL (contrôle de l'en-tête `Host` contre le DNS rebinding). Saisie des cibles, suivi en direct (Server-Sent Events), historique, comparaison et export (HTML, Markdown, JSON, ticket). Tous les fichiers sont embarqués : aucun CDN.

### Interface graphique

`jalon --gui` (ou double-clic sous Windows) ouvre la fenêtre Jalon : mêmes fonctions que l'interface web, sans navigateur ni serveur local. Elle n'existe que sous Windows, où Wails se compile sans cgo ; sous Linux et macOS, `--gui` ouvre l'interface web. Le cache de WebView2 est placé dans `%LOCALAPPDATA%\Jalon\WebView2`.

## Développement

```sh
go vet ./... && go test ./...
GOOS=windows go vet -tags desktop,production ./...     # code de la fenêtre Wails
go test -tags live -run TestLive -v ./internal/probe/   # tests contre le vrai réseau
```

Interface graphique (`frontend/`, Svelte 5 + Vite + TypeScript) : `cd frontend && npm ci && npm run build` produit `frontend/dist`, embarqué dans l'exe Windows (`go build -tags desktop,production`). Pour la voir dans un navigateur sans Windows : `go run ./tools/guimock` puis `cd frontend && npm run dev` (diagnostic de démonstration rejoué).

Architecture : `internal/engine` (cascade + bus d'événements), `internal/gui` + `frontend/` (interface graphique Wails), `internal/ui/session` (logique partagée des interfaces), `internal/probe` (env, dns, tcp, tls, http, http3, trace, captive, proxy), `internal/probe/proto` (smtp, imap, pop3, ssh, rdp, ldap, ftp, banner), `internal/verdict` (règles testées une à une), `internal/history`, `internal/report`, `internal/ui/tui`, `internal/ui/web`, `internal/i18n`. Cahier des charges : [`docs/Structure projet.md`](docs/Structure%20projet.md).

## Licence

[GPL-3.0](LICENSE).

---

## English

Jalon takes one or more targets and runs a cascade of read-only tests — local environment, compared DNS (system vs 1.1.1.1 vs 8.8.8.8, DNS interception, NXDOMAIN hijacking), TCP over IPv4 and IPv6, TLS with dual validation (system store and embedded Mozilla bundle, which reveals TLS interception), HTTP/1.1, HTTP/2 and HTTP/3, protocol probes (SMTP, IMAP, POP3, SSH, RDP, LDAP, FTP, generic banner), MTR-like ICMP and TCP SYN traceroute, captive portal and transparent proxy heuristics — and tells you **where it breaks**, in plain support language, with a ticket-ready summary and an automatic comparison with the previous run.

```sh
jalon --lang en https://example.com smtp://mail.example.com 10.0.0.5:3389
jalon --tui example.com      # terminal UI with live MTR
jalon --web                  # local web UI on 127.0.0.1
jalon --gui                  # graphical interface (Windows; elsewhere: web UI)
```

On Windows, double-clicking `jalon.exe` opens a native window (Wails + WebView2) with the live cascade, multi-target summary, live network path, history and comparison, report preview, export and one-click ticket summary. Without the WebView2 runtime, the local web UI opens in the browser instead.

Exit codes: `0` OK, `1` warning, `2` failure. Jalon never authenticates, never changes anything and relies on no server of its own. Licensed under GPL-3.0.
