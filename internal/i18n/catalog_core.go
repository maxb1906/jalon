package i18n

var _ = add(map[string][2]string{
	// Statuts
	"status.ok":      {"OK", "OK"},
	"status.info":    {"Info", "Info"},
	"status.warn":    {"Avertissement", "Warning"},
	"status.fail":    {"Échec", "Failure"},
	"status.skipped": {"Non exécuté", "Skipped"},

	// Couches
	"layer.env":          {"Environnement local", "Local environment"},
	"layer.dns_global":   {"Interception DNS", "DNS interception"},
	"layer.captive":      {"Portail captif / proxy", "Captive portal / proxy"},
	"layer.dns":          {"DNS", "DNS"},
	"layer.tcp_ipv4":     {"TCP IPv4", "TCP IPv4"},
	"layer.tcp_ipv6":     {"TCP IPv6", "TCP IPv6"},
	"layer.tls":          {"TLS", "TLS"},
	"layer.http":         {"HTTP", "HTTP"},
	"layer.http3":        {"HTTP/3 (QUIC)", "HTTP/3 (QUIC)"},
	"layer.proxy":        {"Proxy transparent", "Transparent proxy"},
	"layer.trace_icmp":   {"Chemin réseau (ICMP)", "Network path (ICMP)"},
	"layer.trace_tcp":    {"Chemin réseau (TCP SYN)", "Network path (TCP SYN)"},
	"layer.proto.smtp":   {"SMTP", "SMTP"},
	"layer.proto.imap":   {"IMAP", "IMAP"},
	"layer.proto.pop3":   {"POP3", "POP3"},
	"layer.proto.ssh":    {"SSH", "SSH"},
	"layer.proto.rdp":    {"RDP", "RDP"},
	"layer.proto.ldap":   {"LDAP", "LDAP"},
	"layer.proto.ftp":    {"FTP", "FTP"},
	"layer.proto.banner": {"Bannière / service", "Banner / service"},

	// Colonnes de synthèse
	"col.target":  {"Cible", "Target"},
	"col.dns":     {"DNS", "DNS"},
	"col.tcp":     {"TCP", "TCP"},
	"col.tls":     {"TLS", "TLS"},
	"col.app":     {"Applicatif", "Application"},
	"col.trace":   {"Chemin", "Path"},
	"col.verdict": {"Verdict", "Verdict"},

	// Divers moteur
	"engine.skipped_no_ip":    {"aucune adresse IP à tester", "no IP address to test"},
	"engine.skipped_no_tcp":   {"aucune connexion TCP n'a abouti", "no TCP connection succeeded"},
	"engine.skipped_not_tls":  {"protocole sans TLS", "protocol without TLS"},
	"engine.skipped_disabled": {"désactivé par option", "disabled by option"},
	"engine.skipped_family":   {"famille exclue par option", "family excluded by option"},
	"engine.target_error":     {"cible invalide : %s", "invalid target: %s"},
	"engine.cancelled":        {"diagnostic interrompu", "diagnostic interrupted"},
})
