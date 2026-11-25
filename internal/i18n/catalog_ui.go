package i18n

var _ = add(map[string][2]string{
	"web.title":       {"Jalon — diagnostic de connectivité", "Jalon — connectivity diagnosis"},
	"web.subtitle":    {"diagnostic de connectivité couche par couche", "layer-by-layer connectivity diagnosis"},
	"web.listening":   {"Interface web : %s (Ctrl+C pour arrêter)", "Web interface: %s (Ctrl+C to stop)"},
	"web.tab_run":     {"Diagnostic", "Diagnosis"},
	"web.tab_history": {"Historique", "History"},
	"web.targets":     {"Cibles (une par ligne)", "Targets (one per line)"},
	"web.proto":       {"Protocole", "Protocol"},
	"web.trace_mode":  {"Traceroute", "Traceroute"},
	"web.no_trace":    {"sans traceroute", "no traceroute"},
	"web.run":         {"Lancer le diagnostic", "Run diagnosis"},
	"web.running":     {"diagnostic en cours…", "diagnosis running…"},
	"web.done":        {"diagnostic terminé", "diagnosis complete"},
	"web.export":      {"Exporter :", "Export:"},
	"web.filter":      {"filtrer par cible", "filter by target"},
	"web.compare":     {"Comparer la sélection (2)", "Compare selection (2)"},
	"web.date":        {"Date", "Date"},
	"web.open":        {"rapport", "report"},
	"web.no_target":   {"aucune cible", "no target"},
	"web.readonly":    {"outil en lecture seule : il observe, ne modifie rien et ne s'authentifie jamais", "read-only tool: it observes, changes nothing and never authenticates"},

	"tui.subtitle": {"diagnostic en lecture seule", "read-only diagnosis"},
	"tui.keys":     {"←/→ cible · m chemin (MTR live) · espace figer · v détails · ↑/↓ défiler · q quitter", "←/→ target · m path (live MTR) · space freeze · v details · ↑/↓ scroll · q quit"},
	"tui.frozen":   {"[figé]", "[frozen]"},
	"tui.running":  {"%s en cours…", "%s running…"},
	"tui.waiting":  {"en attente…", "waiting…"},
	"tui.no_trace": {"pas de traceroute pour cette cible", "no traceroute for this target"},
	"tui.live":     {"en direct", "live"},

	"short.ok":      {"OK", "OK"},
	"short.info":    {"info", "info"},
	"short.warn":    {"alerte", "warn"},
	"short.fail":    {"échec", "fail"},
	"short.skipped": {"—", "—"},

	"hop.host":   {"Hôte", "Host"},
	"hop.loss":   {"Perte", "Loss"},
	"hop.sent":   {"Env.", "Sent"},
	"hop.avg":    {"moy", "avg"},
	"hop.jitter": {"gigue", "jitter"},

	"text.host":          {"Poste : %s (%s) · IP %s · passerelle %s · IP publique %s", "Computer: %s (%s) · IP %s · gateway %s · public IP %s"},
	"text.common":        {"Commun à toutes les cibles", "Common to all targets"},
	"text.synthesis":     {"Synthèse", "Summary"},
	"text.ticket":        {"Résumé ticket", "Ticket summary"},
	"text.changes":       {"Changements depuis le dernier diagnostic (%s)", "Changes since the last diagnosis (%s)"},
	"text.other_network": {"(diagnostic précédent sur un autre réseau)", "(previous diagnosis on another network)"},
	"text.no_changes":    {"aucun changement notable", "no notable change"},

	"ticket.header":  {"Diagnostic Jalon %s du %s — poste %s, IP %s, passerelle %s", "Jalon %s diagnosis of %s — computer %s, IP %s, gateway %s"},
	"ticket.advice":  {"Piste", "Suggestion"},
	"ticket.changes": {"Changements depuis le précédent", "Changes since previous"},

	"html.title":     {"Rapport de diagnostic Jalon", "Jalon diagnostic report"},
	"html.generated": {"Jalon %s — généré le %s", "Jalon %s — generated on %s"},
	"html.layer":     {"Couche", "Layer"},
	"html.result":    {"Résultat", "Result"},

	"usage": {`Jalon — diagnostic de connectivité couche par couche (lecture seule)

Usage :
  jalon [options] cible [cible…]      ex. https://exemple.be  smtp://mail.exemple.be  10.0.0.5:3389
  jalon -f cibles.txt                 une cible par ligne (# = commentaire)
  jalon --tui cible…                  interface terminal (cascade + MTR live)
  jalon --web                         interface web locale (127.0.0.1)
  jalon history [filtre]              liste l'historique ; « history purge 30d » purge
  jalon diff <id1> <id2>              compare deux diagnostics

Codes de sortie : 0 OK, 1 avertissement, 2 échec.

Options :`, `Jalon — layer-by-layer connectivity diagnosis (read-only)

Usage:
  jalon [options] target [target…]    e.g. https://example.com  smtp://mail.example.com  10.0.0.5:3389
  jalon -f targets.txt                one target per line (# = comment)
  jalon --tui target…                 terminal interface (cascade + live MTR)
  jalon --web                         local web interface (127.0.0.1)
  jalon history [filter]              list history; "history purge 30d" purges
  jalon diff <id1> <id2>              compare two diagnoses

Exit codes: 0 OK, 1 warning, 2 failure.

Options:`},
	"flag.f":              {"fichier de cibles (une par ligne, « - » = entrée standard)", "targets file (one per line, \"-\" = stdin)"},
	"flag.no-trace":       {"ne pas faire de traceroute", "skip traceroute"},
	"flag.trace-mode":     {"mode de traceroute : icmp, tcp ou auto", "traceroute mode: icmp, tcp or auto"},
	"flag.ipv4":           {"IPv4 uniquement", "IPv4 only"},
	"flag.ipv6":           {"IPv6 uniquement", "IPv6 only"},
	"flag.proto":          {"forcer le protocole : http, https, smtp, imap, pop3, ssh, rdp, ldap, ftp, banner", "force protocol: http, https, smtp, imap, pop3, ssh, rdp, ldap, ftp, banner"},
	"flag.timeout":        {"délai par étape", "per-step timeout"},
	"flag.json":           {"sortie JSON", "JSON output"},
	"flag.report":         {"écrire un rapport : html, md ou json", "write a report: html, md or json"},
	"flag.o":              {"chemin du rapport", "report path"},
	"flag.lang":           {"langue : fr ou en", "language: fr or en"},
	"flag.parallel":       {"nombre de cibles traitées en parallèle", "number of targets processed in parallel"},
	"flag.parallel-trace": {"ne pas sérialiser les traceroutes entre cibles", "do not serialize traceroutes across targets"},
	"flag.no-history":     {"ne pas enregistrer ni comparer l'historique", "do not record or compare history"},
	"flag.history-dir":    {"dossier d'historique (défaut : jalon-history à côté de l'exécutable)", "history folder (default: jalon-history next to the executable)"},
	"flag.web":            {"lancer l'interface web locale", "start the local web interface"},
	"flag.no-browser":     {"avec --web : ne pas ouvrir le navigateur", "with --web: do not open the browser"},
	"flag.tui":            {"lancer l'interface terminal", "start the terminal interface"},
	"flag.no-rdns":        {"pas de résolution inverse des sauts", "no reverse DNS for hops"},
	"flag.asn":            {"afficher l'ASN des sauts (requête DNS vers Team Cymru)", "show hop ASN (DNS query to Team Cymru)"},
	"flag.h3":             {"tenter QUIC même sans annonce Alt-Svc", "try QUIC even without an Alt-Svc announcement"},
	"flag.probes":         {"sondes par saut pour le traceroute", "probes per hop for traceroute"},
	"flag.max-hops":       {"nombre maximal de sauts", "maximum number of hops"},
	"flag.ticket":         {"n'afficher que le résumé ticket", "print only the ticket summary"},
	"flag.v":              {"afficher aussi les informations détaillées", "also show detailed information"},
	"flag.no-color":       {"sans couleurs", "no colors"},
	"flag.version":        {"afficher la version", "print version"},

	"cli.bad_lang":          {"langue inconnue %s (fr ou en)", "unknown language %s (fr or en)"},
	"cli.bad_trace_mode":    {"mode de traceroute inconnu %s (icmp, tcp, auto)", "unknown traceroute mode %s (icmp, tcp, auto)"},
	"cli.bad_proto":         {"protocole inconnu %s (%s)", "unknown protocol %s (%s)"},
	"cli.bad_report":        {"format de rapport inconnu %s (html, md, json)", "unknown report format %s (html, md, json)"},
	"cli.ipv4_ipv6":         {"--ipv4 et --ipv6 sont incompatibles", "--ipv4 and --ipv6 are mutually exclusive"},
	"cli.history_error":     {"historique indisponible : %s", "history unavailable: %s"},
	"cli.report_written":    {"rapport écrit : %s", "report written: %s"},
	"cli.running":           {"diagnostic de %s cible(s), lecture seule", "diagnosing %s target(s), read-only"},
	"cli.history_dir":       {"Historique : %s", "History: %s"},
	"cli.history_empty":     {"aucun diagnostic enregistré", "no recorded diagnosis"},
	"cli.purged":            {"%s diagnostic(s) supprimé(s) de %s", "%s diagnosis(es) removed from %s"},
	"cli.bad_age":           {"durée invalide %s (ex. 30d, 2w, 12h)", "invalid age %s (e.g. 30d, 2w, 12h)"},
	"cli.diff_usage":        {"usage : jalon diff <id1> <id2>", "usage: jalon diff <id1> <id2>"},
	"cli.diff_header":       {"Comparaison %s (%s) → %s (%s)", "Comparing %s (%s) → %s (%s)"},
	"cli.diff_other_target": {"attention : cibles différentes", "warning: different targets"},
})
