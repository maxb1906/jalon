# Jalon

[Français](README.md) · **English**

[![CI](https://github.com/maxb1906/jalon/actions/workflows/ci.yml/badge.svg)](https://github.com/maxb1906/jalon/actions/workflows/ci.yml)
[![Licence: GPL-3.0](https://img.shields.io/badge/licence-GPL--3.0-blue.svg)](LICENSE)

**Layer-by-layer connectivity diagnosis and application traceroute.** A single portable executable, nothing to install: give it one or more targets (`https://example.com`, `smtp://mail.example.com`, `10.0.0.5:3389`…) and it runs a cascade of tests until it can tell **where it breaks**, in plain support language.

Same family as [Arpent](https://github.com/maxb1906/arpent) (network audit) and [Aplomb](https://github.com/maxb1906/aplomb) (Windows audit): portable executable, read-only, exportable reports.

## What Jalon tests

1. **Local environment**: interface, gateway (ping), MTU, configured DNS, proxy (variables, WinINet/WinHTTP, macOS, PAC/WPAD), available privileges
2. **Compared DNS**: system resolver / 1.1.1.1 / 8.8.8.8, DNS interception (UDP 53 vs DoH, `whoami.cloudflare`, `o-o.myaddr.l.google.com`), NXDOMAIN hijacking, DNSSEC, MX/SRV
3. **TCP** over IPv4 and IPv6 separately: refused (RST) / filtered (timeout) / unreachable, "IPv6 advertised but broken"
4. **TLS**: version, cipher suite, ALPN, SNI, chain, expiry, host name, self-signed, missing intermediate, weak algorithms, OCSP stapling, **dual validation** against the system store and an embedded Mozilla bundle → detects **TLS interception** (Zscaler, Fortinet, Kaspersky…)
5. **HTTP/1.1 and HTTP/2** (DNS / TCP / TLS / TTFB / total timings, redirects, notable headers), **HTTP/3** via Alt-Svc then QUIC
6. **Protocol probes**: SMTP, IMAP, POP3 (STARTTLS or direct TLS), SSH (KEXINIT, obsolete algorithms, host key fingerprint), RDP (X.224, NLA), LDAP (StartTLS, LDAPS, anonymous RootDSE), FTP (FEAT, AUTH TLS), generic banner
7. **Network path**, MTR-style: ICMP and **per-hop TCP SYN** (when privileges allow), loss, latency, jitter, silent hops, loops, propagated vs isolated loss, ICMP / TCP comparison
8. **Captive portal** (Google, Microsoft, Apple) and **transparent proxy** heuristics (headers, non-routable addresses that answer, TCP vs ICMP delay, SYN-ACK TTL)

Output: a **verdict** first ("The local DNS returns a different IP than public resolvers → filtering likely"), a suggested action, the detail of each step, a **comparison with the previous run** and a **ticket-ready summary**.

> **Read-only.** Jalon observes, changes nothing on the machine, never authenticates and stops at each protocol's negotiation. No Jalon-owned external service: nothing is sent anywhere but to the targets and the public resolvers/probes listed above.

## Getting started

1. Download the archive for your platform from the [Releases](https://github.com/maxb1906/jalon/releases): `jalon_<version>_windows_amd64.zip` (or `windows_arm64`, `linux_*`, `darwin_*` as `.tar.gz`), and extract it, for instance to a USB stick.
2. **On Windows, double-click `jalon.exe`**: the web interface opens in your browser (keep the console window open while you use it).
3. Enter one or more targets, follow the cascade live, then export the report.

All data lives in the `jalon-data/` folder **next to the executable**: preferences (`config.yaml`), history (`historique/`) and reports (`rapports/`). Nothing is written to the registry or to `%APPDATA%`. If that folder is not writable (read-only stick), Jalon says so and uses the system temporary folder.

> **Windows blocks the executable**: it is not signed yet. Depending on the PC:
> - **SmartScreen** ("Windows protected your PC"): click "More info" then "Run anyway".
> - **Smart App Control** (Windows 11): the executable is blocked **with no button to bypass it** and no per-app exception. The only way is to turn it off (Windows Security → *App & browser control* → *Smart App Control settings* → *Off*); since the April 2026 Windows 11 update it can be turned back on afterwards without reinstalling Windows. On a customer's PC, only turn it off with their consent.
> - A tool that opens raw ICMP sockets may also be flagged by some **antivirus** software.
>
> Check the hash against the release's `SHA256SUMS` file. Code signing (SignPath Foundation, after Arpent) will lift these blocks.

## Command line

Open a terminal (PowerShell or `cmd`) in the executable's folder:

```
jalon https://example.com
jalon smtp://mail.example.com imaps://mail.example.com 10.0.0.5:3389
jalon -f targets.txt --format html,md       # one target per line, # = comment
jalon tui https://example.com               # terminal UI: cascade + live MTR
jalon web                                   # local web UI (127.0.0.1, token)
jalon --json example.com > report.json      # JSON on standard output
jalon --ticket example.com                  # ticket summary only
jalon --format html --report-lang fr example.com
jalon history                               # history; "jalon history purge 30d"
jalon diff <id1> <id2>                      # compare two runs
jalon version
```

| Option | Purpose |
|---|---|
| `--trace-mode icmp\|tcp\|auto` | traceroute mode (auto: ICMP, plus TCP SYN when privileges allow) |
| `--no-trace` | no traceroute |
| `--ipv4` / `--ipv6` (`-4` / `-6`) | a single address family |
| `--proto smtp` | force the protocol (http, https, smtp, imap, pop3, ssh, rdp, ldap, ftp, banner) |
| `--timeout 5s` | per-step timeout |
| `--format html,md,json,ticket` | reports to write, into `jalon-data/rapports/` (`--out <folder>` for another folder, `-o <file>` for a single format) |
| `--report-lang fr\|en` | report language (default: `config.yaml`, else the tool's language) |
| `--json`, `--ticket` | what is printed on standard output |
| `--lang fr\|en` | tool language (default: system language; `JALON_LANG` variable) |
| `--data <folder>` | data folder (`JALON_DATA` variable) |
| `--parallel 4` | targets processed in parallel (traceroutes stay serialised unless `--parallel-trace`) |
| `--h3` | try QUIC even without an Alt-Svc announcement |
| `--asn`, `--no-rdns`, `--probes 5`, `--max-hops 30` | traceroute options |
| `--no-history`, `--history-dir` | history |
| `-v` | also show detailed information |

The former `--web`, `--tui` and `--report <format>` forms are still accepted.

The protocol is inferred from the scheme (`smtp://`, `submission://`, `smtps://`, `imaps://`, `pop3s://`, `ssh://`, `rdp://`, `ldap://`, `ldaps://`, `ftp://`, `tcp://`, `tls://`) or from the standard port. A target with neither scheme nor port is tested over HTTPS. A target actually named `web` or `tui` is written `https://web` or `web:443`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | diagnosis OK |
| `1` | warning |
| `2` | diagnosis failed |
| `3` | Jalon usage or execution error (invalid option, unreadable target file, report that cannot be written…) |

A script can thus tell "the target is broken" (`2`) from "the command is wrong" (`3`).

### Privileges and traceroute

| System | ICMP | Per-hop TCP SYN |
|---|---|---|
| Windows | always (`IcmpSendEcho`, IPv4) | administrator (raw ICMP socket, no Npcap) |
| Linux | root, `CAP_NET_RAW`, or unprivileged ping (`net.ipv4.ping_group_range`) | root or `CAP_NET_RAW` |
| macOS | always (ICMP datagram socket; root recommended) | root |

Without the privileges, the mode is shown as "not available" with the reason, never a silent failure. On Linux, `sudo setcap cap_net_raw+ep ./jalon` enables every mode without root.

## Configuration

`jalon-data/config.yaml` (created with the data folder) has the same shape as in Arpent and Aplomb:

```yaml
technician: "Name"           # report cover page
lang: ""                     # tool language (empty: system)
report_lang: ""              # report language (empty: the tool's)
issuer:                      # report issuer
  name: "Name"
  company: "My company"
  contact: "1 Example Street, 4000 Liège · contact@example.com"
  legal: "VAT BE0123.456.789"   # report footer
  color: "#1f5f8b"              # main report colour
  logo: logo.png                # relative to jalon-data/
```

## History

Each run is saved as JSON in `jalon-data/historique/`. It is indexed by target and by local network (gateway + estimated public IP), and automatically compared with the previous one: resolved IPs, certificate, network path, latency, a layer going from OK to failure. History is never sent over the network. The former `jalon-history/` folder of 1.0.x versions is moved automatically; history left in `%APPDATA%\jalon\history` must be copied by hand into `jalon-data\historique`.

## Web interface

`jalon web` listens on `127.0.0.1` only, on a random port, with a token in the URL and a check of the `Host` header (host and port, against DNS rebinding). Target entry, live progress (Server-Sent Events), history, comparison and export (HTML, Markdown, JSON, ticket). Every file is embedded: no CDN.

## Building

Requirements: [Go](https://go.dev/dl/) (version from `go.mod`). No CGO: cross-compiling works from any system.

```sh
make test        # tests (with the race detector)
make windows     # dist/jalon-windows-amd64.exe
make build-all   # windows, linux, darwin × amd64, arm64
make all         # format, vet (Linux, Windows, macOS), tests, binaries
go test -tags live -run TestLive -v ./internal/probe/   # tests against the real network
```

CI also runs the executable on Windows (diagnosis of `127.0.0.1`, reports, web interface). Releases are published by GitHub Actions + GoReleaser on each `vX.Y.Z` tag.

## Contributing

- Translations: `assets/i18n/fr.json` and `en.json` (same keys and same `{1}`, `{2}`… variables, checked by the tests).
- Architecture: `internal/engine` (cascade + event bus), `internal/probe` (env, dns, tcp, tls, http, http3, trace, captive, proxy), `internal/probe/proto` (smtp, imap, pop3, ssh, rdp, ldap, ftp, banner), `internal/verdict` (rules tested one by one), `internal/history`, `internal/report`, `internal/config`, `internal/ui/tui`, `internal/ui/web`, `internal/i18n`.
- Scope and decisions (in French): [docs/STRUCTURE.md](docs/STRUCTURE.md).

## Licence

[GPL-3.0](LICENSE).
