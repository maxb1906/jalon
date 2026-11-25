# Jalon — Diagnostic de connectivité et traceroute applicatif

> **Statut : cadrage terminé, développement pas commencé.**
> Même famille qu'[[Arpent]] (audit réseau) et [[Aplomb]] (audit Windows) : exe portable, lecture seule, rapports exportables.
> Ce fichier consigne tous les choix et sert de suivi d'implémentation pour Claude Code.

## 0. Décisions prises

| Sujet | Choix |
|---|---|
| Nom | **Jalon** |
| Interfaces | CLI + TUI + UI web locale (`jalon --web`) |
| HTTP/3 | Dès la v1 |
| Proxy transparent | 100 % autonome, aucun service externe à moi (pas d'endpoint écho sur le VPS) |
| Traceroute TCP SYN par saut | En v1, activé seulement si les droits sont disponibles (admin / root, Npcap sous Windows) |
| Plateformes | Windows, Linux, macOS (amd64 + arm64) |
| Cibles non-HTTP | Sondes par protocole (SMTP, IMAP, POP3, SSH, RDP, LDAP, FTP) |
| Historique | Oui, historique local avec comparaison automatique au dernier diagnostic |
| Multi-cible | Oui : plusieurs cibles en arguments ou dans un fichier |
| Stack | Go |
| Licence | GPL-3.0 |
| Langues | Français + anglais |
| Dépôt | GitHub public `maxb1906/jalon` |
| Nature | Lecture seule : diagnostique, ne modifie rien sur la machine |

**Non-objectifs v1** : pas de monitoring continu ni d'agent, pas de correction automatique, pas de test de débit, pas de dépendance à un serveur à moi.

## 1. Concept

Outil de dépannage orienté support. On lui donne une ou plusieurs cibles (URL, nom d'hôte, IP, `hôte:port` ou `schéma://hôte`) et il déroule une **cascade de tests**, couche par couche, jusqu'à dire **où ça casse** en langage support :

1. Environnement local (interface, passerelle, proxy configuré)
2. Résolution DNS comparée (DNS local / 1.1.1.1 / 8.8.8.8)
3. Chemin réseau saut par saut (façon MTR)
4. Connexion TCP au port cible
5. Handshake et chaîne TLS
6. Couche applicative : HTTP (1.1 / 2 / 3) ou sonde du protocole concerné
7. Détection de proxy transparent et de portail captif

Sortie : un verdict en tête (« Le DNS local renvoie une IP différente des résolveurs publics → filtrage probable »), le détail de chaque étape, la comparaison avec le diagnostic précédent et un résumé prêt à coller dans un ticket.

## 2. Périmètre fonctionnel

### 2.1 Environnement local (exécuté une seule fois, même en multi-cible)
- Interface active, IP, passerelle, MTU
- DNS configurés par l'OS
- Proxy système : variables `HTTP(S)_PROXY`, proxy WinHTTP/WinINet, PAC / WPAD
- Ping de la passerelle (le problème est-il avant même la box ?)
- Droits disponibles (admin/root, Npcap présent) → détermine les modes de traceroute possibles, affiché dans le rapport

### 2.2 DNS comparé
- Requêtes A, AAAA, CNAME vers : résolveur système, 1.1.1.1, 8.8.8.8 (UDP, repli TCP)
- Comparaison : réponses identiques ? TTL ? temps de réponse ?
- **Interception DNS** : requête UDP 53 vers 1.1.1.1 comparée à DoH (`https://1.1.1.1/dns-query`, `https://dns.google/dns-query`). Requêtes « qui suis-je » (`whoami.cloudflare` CH TXT, `o-o.myaddr.l.google.com` TXT) pour voir quel résolveur répond réellement
- **NXDOMAIN hijacking** : requête sur un domaine aléatoire inexistant ; si on obtient une IP → le FAI ou la box redirige
- Drapeau DNSSEC (AD) si disponible
- Enregistrements spécifiques selon la sonde : MX pour SMTP, SRV quand pertinent

### 2.3 Chemin réseau (MTR-like)
- Traceroute par TTL croissant, N sondes par saut : perte, latence min/moy/max, gigue
- Modes :
  - **ICMP** (par défaut, sans droits) : `IcmpSendEcho2` sous Windows, ping socket non privilégié sous Linux/macOS (repli raw socket si root)
  - **TCP SYN par saut** (v1, si droits) : vers le port réel de la cible ; traverse les pare-feux qui filtrent l'ICMP. Windows : Npcap requis ; Linux : root ou `CAP_NET_RAW` ; macOS : root
  - Si les droits manquent : le mode est marqué « non disponible » avec la raison, jamais d'échec silencieux
- Résolution inverse des sauts (désactivable), ASN optionnel
- Analyse : boucle, saut muet, perte qui démarre à un saut et se propage jusqu'au bout (vraie perte) vs perte isolée (simple limitation ICMP du routeur)
- Comparaison ICMP vs TCP quand les deux tournent : chemin qui diffère → filtrage ou routage par protocole

### 2.4 TCP
- Temps de connexion au port cible (SYN → établi), IPv4 et IPv6 séparément
- Distinction claire : refus (RST) / timeout (filtré) / injoignable (ICMP)
- IPv6 vs IPv4 : détecte le cas classique « IPv6 annoncé mais cassé »

### 2.5 TLS
- Version, suite, ALPN négocié, SNI, temps du handshake
- Chaîne complète : expiration (et alerte si < 30 jours), nom d'hôte, intermédiaire manquant, auto-signé, algorithmes faibles
- Validation double : magasin système **et** bundle Mozilla embarqué
- **Interception TLS** : chaîne valide pour le système mais pas pour Mozilla → CA d'entreprise ou antivirus qui déchiffre (Zscaler, Fortinet, Kaspersky…), émetteur affiché
- OCSP stapling présent ou non
- S'applique aussi aux protocoles en TLS direct (993, 995, 465, 636…) et après STARTTLS

### 2.6 HTTP
- Décomposition des temps façon `curl -w` : DNS / TCP / TLS / TTFB / total
- HTTP/1.1, HTTP/2 via ALPN, **HTTP/3** via en-tête `Alt-Svc` puis tentative QUIC (et tentative QUIC directe si demandée)
- Alt-Svc annonce h3 mais QUIC échoue → UDP 443 probablement bloqué
- Code de statut, chaîne de redirections, en-têtes notables (`Server`, `Via`, `X-Cache`…)

### 2.7 Sondes par protocole
Le protocole est déduit du schéma (`smtp://`, `imaps://`, `ssh://`, `rdp://`…) ou du port standard ; forçable avec `--proto`.

| Protocole | Ports | Ce que vérifie la sonde |
|---|---|---|
| SMTP | 25, 587, 465 | Bannière 220, `EHLO`, extensions annoncées, `STARTTLS` (587/25) ou TLS direct (465), puis analyse TLS ; MX du domaine si cible = domaine mail. Alerte si le port 25 sortant est bloqué (fréquent chez les FAI) |
| IMAP | 143, 993 | Bannière, `CAPABILITY`, `STARTTLS` ou TLS direct |
| POP3 | 110, 995 | Bannière `+OK`, `CAPA`, `STLS` ou TLS direct |
| SSH | 22 | Bannière de version, `KEXINIT` : algorithmes d'échange de clés, chiffrement, clés d'hôte ; algorithmes obsolètes signalés ; empreinte de la clé d'hôte (aucune authentification tentée) |
| RDP | 3389 | Négociation X.224 : protocoles acceptés (RDP natif / TLS / NLA-CredSSP), puis certificat TLS ; alerte si NLA non requis |
| LDAP | 389, 636 | `StartTLS` (extended op) ou LDAPS, puis analyse TLS ; lecture du RootDSE anonyme si autorisé |
| FTP | 21 | Bannière, `FEAT`, `AUTH TLS` |
| Autre port | — | TCP + détection TLS direct + lecture de bannière générique |

Règle commune : **aucune authentification, aucune commande qui modifie un état**. On s'arrête à la négociation.

### 2.8 Proxy transparent et portail captif (100 % autonome)
- Sondes de portail captif standard (`connectivitycheck.gstatic.com/generate_204`, `www.msftconnecttest.com/connecttest.txt`, `captive.apple.com/hotspot-detect.html`) : réponse attendue vs réelle, au moins deux sources pour conclure
- Proxy transparent, par heuristiques locales :
  - en-têtes `Via`, `X-Forwarded-For`, `X-Cache`, `Proxy-*` présents dans la réponse
  - réponse HTTP sur le port 80 d'une IP qui ne devrait pas en avoir (ex. IP d'un résolveur DNS)
  - TTL des paquets reçus incohérent avec la distance mesurée au traceroute (la réponse arrive « de trop près »)
  - délai TCP sur le port 80 anormalement plus court que la latence ICMP vers la même IP
  - interception TLS (cf. 2.5)
- Toujours formulé « probable » / « à vérifier », jamais en certitude

## 3. Multi-cible et historique

### Multi-cible
- `jalon cible1 cible2 …` ou `jalon -f cibles.txt` (une cible par ligne, `#` = commentaire)
- L'environnement local (2.1) et les sondes de portail captif ne tournent qu'une fois
- Cibles traitées en parallèle avec une limite de concurrence (`--parallel`, défaut 4) ; le traceroute est sérialisé par défaut pour ne pas fausser les mesures
- Rapport unique avec un tableau de synthèse (une ligne par cible, statut par couche) puis le détail

### Historique local
- Chaque diagnostic est enregistré en JSON dans un dossier `jalon-history/` **à côté de l'exe** (portable) ; repli sur le dossier de config utilisateur si l'emplacement n'est pas inscriptible
- Historique indexé par cible (et par réseau local : passerelle + IP publique estimée, pour distinguer « au bureau » et « à la maison »)
- **Comparaison automatique** avec le dernier diagnostic de la même cible : IP résolues changées, certificat changé, chemin réseau différent, latence en hausse au-delà d'un seuil, couche passée de OK à échec
- Options : `--no-history`, `jalon history` (liste), `jalon diff <id1> <id2>`, purge par âge
- Aucun envoi réseau de l'historique

## 4. Interfaces et sorties

### CLI
- `jalon https://exemple.be`, `jalon smtp://mail.exemple.be`, `jalon 10.0.0.5:3389`
- Options : `--no-trace`, `--trace-mode icmp|tcp|auto`, `--ipv4/--ipv6`, `--proto`, `--timeout`, `--json`, `--report html|md`, `--lang fr|en`
- Codes de sortie exploitables en script : 0 OK, 1 avertissement, 2 échec

### TUI
- Vue cascade qui se remplit en direct, une couche par ligne avec statut
- Panneau MTR live (rafraîchissement continu, touche pour figer)
- Navigation entre cibles en multi-cible

### UI web locale
- `jalon --web` : même exe, serveur HTTP sur **127.0.0.1 uniquement**, port aléatoire, jeton dans l'URL, ouvre le navigateur
- Saisie de la ou des cibles, suivi en direct (Server-Sent Events), consultation et comparaison de l'historique, export des rapports
- Fichiers web embarqués dans le binaire (`embed`), aucun CDN externe

### Rapports
- HTML autonome, Markdown, JSON (même style qu'Arpent / Aplomb)
- **Résumé ticket** : 5 à 10 lignes en texte brut, copiable, sans jargon inutile
- Section « Changements depuis le dernier diagnostic » si historique

## 5. Architecture technique

### Briques Go
| Besoin | Brique |
|---|---|
| DNS vers un résolveur précis, DoH | `github.com/miekg/dns` + `net/http` |
| ICMP / TTL | `golang.org/x/net/icmp`, `ipv4`, `ipv6` ; `IcmpSendEcho2` (iphlpapi) sous Windows |
| TCP SYN par saut | raw sockets Linux/macOS ; Npcap via `gopacket/pcap` sous Windows (chargement dynamique de `wpcap.dll`, à valider sans cgo) |
| TLS bas niveau | `crypto/tls` (`VerifyConnection`, `ConnectionState`) |
| HTTP/2 | `net/http` + `golang.org/x/net/http2` |
| HTTP/3 / QUIC | `github.com/quic-go/quic-go` |
| Temps détaillés | `net/http/httptrace` |
| SSH (KEXINIT seulement) | parseur maison du paquet KEXINIT (pas d'auth, donc pas besoin de `x/crypto/ssh` complet) |
| RDP | négociation X.224 maison |
| LDAP StartTLS | `github.com/go-ldap/ldap/v3` |
| TUI | `charmbracelet/bubbletea` + `lipgloss` |
| UI web | `net/http`, `html/template`, `embed`, SSE, JS vanilla |
| Bundle CA Mozilla | `golang.org/x/crypto/x509roots/fallback` |
| i18n | catalogues FR/EN embarqués |

### Moteur de cascade
- Chaque étape = un `Probe` : `Run(ctx) Result` avec statut `OK / Warn / Fail / Skipped`, mesures, explication FR/EN
- `context.WithTimeout` par étape + budget global ; sondes indépendantes en parallèle (les 3 résolveurs DNS, IPv4/IPv6, sondes captives)
- Une étape en échec n'arrête pas tout : les suivantes passent en `Skipped` avec la raison, ou continuent sur une IP de repli (ex. IP obtenue via 1.1.1.1 si le DNS local est cassé)
- Bus d'événements unique consommé par la CLI, la TUI et l'UI web : le moteur ne connaît pas l'interface
- **Moteur de règles** en fin de course qui croise les résultats pour produire le verdict (ex. DNS OK + TCP timeout + traceroute qui meurt au saut 2 → « blocage au niveau du routeur/pare-feu local »). Règles déclarées dans le code, testées une par une

### Arborescence indicative
```
cmd/jalon/            point d'entrée, parsing des options
internal/engine/      cascade, contexte, bus d'événements
internal/probe/       env, dns, trace, tcp, tls, http, captive, proxy
internal/probe/proto/ smtp, imap, pop3, ssh, rdp, ldap, ftp, banner
internal/verdict/     règles de diagnostic
internal/history/     stockage JSON, diff
internal/report/      html, md, json, ticket
internal/ui/tui/      bubbletea
internal/ui/web/      serveur local + assets embarqués
internal/i18n/        fr, en
```

## 6. Jalons de développement
1. [ ] Squelette CLI + moteur de cascade + bus d'événements + rapport JSON
2. [ ] Environnement local + détection des droits
3. [ ] DNS comparé + interception DNS + NXDOMAIN
4. [ ] TCP (v4/v6) + TLS (chaîne, double validation, interception)
5. [ ] HTTP 1.1/2 + décomposition des temps
6. [ ] HTTP/3 (Alt-Svc + QUIC)
7. [ ] Sondes par protocole : SMTP, IMAP, POP3, puis SSH, RDP, LDAP, FTP, bannière générique
8. [ ] Portail captif + heuristiques de proxy transparent
9. [ ] Traceroute ICMP (3 OS) puis TCP SYN (raw / Npcap)
10. [ ] Moteur de règles + verdict + résumé ticket
11. [ ] Multi-cible
12. [ ] Historique + comparaison + `history` / `diff`
13. [ ] TUI (cascade + MTR live)
14. [ ] UI web locale
15. [ ] Rapports HTML / Markdown
16. [ ] i18n FR/EN complète
17. [ ] Builds Windows / Linux / macOS (amd64 + arm64), release GitHub, README

## 7. Risques
- Faux positifs du traceroute (routeurs qui limitent l'ICMP) → le verdict raisonne sur la propagation de la perte, pas sur un saut isolé
- Npcap sous Windows : licence Npcap non redistribuable gratuitement → Jalon ne l'embarque pas, il le détecte s'il est installé et explique comment l'obtenir
- Antivirus qui signalent un exe qui ouvre des sockets ICMP/raw → binaire signé à terme, ou doc d'exclusion
- Sondes captives qui dépendent de services Google/Microsoft/Apple → au moins deux sources, verdict prudent
- Heuristiques de proxy transparent sans serveur externe → moins fiables qu'un écho ; toujours formulées en « probable »
- Sondes de protocoles : rester strictement en négociation, pour ne pas déclencher de blocage (fail2ban, verrouillage de compte)
- Taille du binaire (quic-go + bubbletea + assets web) : à surveiller, viser < 25 Mo

## 8. Nom
**Jalon** : en arpentage, les jalons sont les piquets plantés le long d'un tracé pour vérifier chaque point du chemin, exactement ce que fait l'outil, saut par saut et couche par couche. Paire naturelle avec **Arpent**. Court, prononçable en FR et EN, commande `jalon` agréable à taper.
