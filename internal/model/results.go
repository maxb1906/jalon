package model

import (
	"time"

	"github.com/maxb1906/jalon/internal/i18n"
)

// ---------- Environnement local ----------

// Iface décrit une interface réseau.
type Iface struct {
	Name    string   `json:"name"`
	Addrs   []string `json:"addrs"`
	MTU     int      `json:"mtu"`
	Default bool     `json:"default"`
}

// ProxyConf décrit un proxy configuré sur le poste.
type ProxyConf struct {
	Source string `json:"source"` // env, wininet, winhttp, macos
	Value  string `json:"value"`
}

// Privileges décrit les droits disponibles et les modes de traceroute.
type Privileges struct {
	Admin       bool     `json:"admin"`
	CapNetRaw   bool     `json:"cap_net_raw,omitempty"`
	UnprivPing  bool     `json:"unpriv_ping,omitempty"`
	Npcap       bool     `json:"npcap,omitempty"`
	ICMPTrace   bool     `json:"icmp_trace"`
	ICMPReason  i18n.Msg `json:"icmp_reason,omitzero"`
	TCPTrace    bool     `json:"tcp_trace"`
	TCPReason   i18n.Msg `json:"tcp_reason,omitzero"`
	ICMPMethod  string   `json:"icmp_method,omitempty"`
	TCPMethod   string   `json:"tcp_method,omitempty"`
	RawSniffTTL bool     `json:"raw_sniff_ttl,omitempty"`
	LocalIPv4   string   `json:"-"`
}

// EnvResult regroupe l'environnement local (exécuté une seule fois).
type EnvResult struct {
	Base
	Hostname    string      `json:"hostname"`
	OS          string      `json:"os"`
	Ifaces      []Iface     `json:"ifaces"`
	LocalIPv4   string      `json:"local_ipv4,omitempty"`
	LocalIPv6   string      `json:"local_ipv6,omitempty"`
	Gateways    []string    `json:"gateways,omitempty"`
	DNSServers  []string    `json:"dns_servers,omitempty"`
	DNSUpstream []string    `json:"dns_upstream,omitempty"`
	Proxies     []ProxyConf `json:"proxies,omitempty"`
	PAC         string      `json:"pac,omitempty"`
	WPAD        string      `json:"wpad,omitempty"`
	GatewayPing *PingStat   `json:"gateway_ping,omitempty"`
	Priv        Privileges  `json:"privileges"`
	PublicIP    string      `json:"public_ip,omitempty"`
}

// PingStat résume une série d'échos ICMP.
type PingStat struct {
	Target string  `json:"target"`
	Sent   int     `json:"sent"`
	Recv   int     `json:"recv"`
	MinMs  float64 `json:"min_ms"`
	AvgMs  float64 `json:"avg_ms"`
	MaxMs  float64 `json:"max_ms"`
	TTL    int     `json:"ttl,omitempty"`
	Error  string  `json:"error,omitempty"`
}

// ---------- DNS ----------

// DNSAnswer est la réponse d'un résolveur pour un nom.
type DNSAnswer struct {
	Resolver  string   `json:"resolver"` // libellé : system, 1.1.1.1, 8.8.8.8, os
	Server    string   `json:"server,omitempty"`
	Transport string   `json:"transport,omitempty"` // udp, tcp, doh, os
	A         []string `json:"a,omitempty"`
	AAAA      []string `json:"aaaa,omitempty"`
	CNAME     []string `json:"cname,omitempty"`
	TTL       uint32   `json:"ttl,omitempty"`
	RTTMs     float64  `json:"rtt_ms"`
	Rcode     string   `json:"rcode,omitempty"`
	AD        bool     `json:"ad,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// OK indique une réponse exploitable.
func (a DNSAnswer) OK() bool { return a.Error == "" && a.Rcode == "NOERROR" }

// IPs renvoie toutes les adresses de la réponse.
func (a DNSAnswer) IPs() []string { return append(append([]string{}, a.A...), a.AAAA...) }

// DNSResult est le DNS comparé pour une cible.
type DNSResult struct {
	Base
	Name        string      `json:"name"`
	Answers     []DNSAnswer `json:"answers"`
	IPv4        []string    `json:"ipv4,omitempty"` // adresses retenues
	IPv6        []string    `json:"ipv6,omitempty"`
	Fallback    bool        `json:"fallback,omitempty"` // adresses issues d'un résolveur public
	MX          []string    `json:"mx,omitempty"`
	SRV         []string    `json:"srv,omitempty"`
	ConnectHost string      `json:"connect_host,omitempty"` // hôte réellement contacté (MX)
	Verdict     string      `json:"verdict"`                // same, cdn, differs, local_fail, local_nx, nx, all_fail
}

// DNSGlobal regroupe les tests d'interception DNS (une seule fois).
type DNSGlobal struct {
	Base
	WhoamiCF        string      `json:"whoami_cloudflare,omitempty"`
	CFPop           string      `json:"cloudflare_pop,omitempty"`
	CFPopDoH        string      `json:"cloudflare_pop_doh,omitempty"`
	GoogleEgress    string      `json:"google_egress,omitempty"`
	GoogleEgressDoH string      `json:"google_egress_doh,omitempty"`
	UDPvsDoH        []DNSAnswer `json:"udp_vs_doh,omitempty"`
	Intercepted     bool        `json:"intercepted"`
	NXName          string      `json:"nx_name,omitempty"`
	NXHijack        bool        `json:"nx_hijack"`
	NXAnswer        []string    `json:"nx_answer,omitempty"`
	DNSSEC          bool        `json:"dnssec_ad"`
}

// ---------- TCP ----------

// TCPResult est une tentative de connexion pour une famille d'adresses.
type TCPResult struct {
	Base
	Family  string  `json:"family"` // ipv4 / ipv6
	IP      string  `json:"ip,omitempty"`
	Port    int     `json:"port"`
	Outcome string  `json:"outcome"` // connected, refused, timeout, unreachable, no_address, no_local, error
	RTTMs   float64 `json:"rtt_ms,omitempty"`
	Error   string  `json:"error,omitempty"`
}

// ---------- TLS ----------

// CertInfo décrit un certificat de la chaîne.
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	IPs        []string  `json:"ips,omitempty"`
	SigAlg     string    `json:"sig_alg"`
	KeyType    string    `json:"key_type"`
	KeyBits    int       `json:"key_bits,omitempty"`
	SHA256     string    `json:"sha256"`
	IsCA       bool      `json:"is_ca,omitempty"`
	SelfSigned bool      `json:"self_signed,omitempty"`
}

// TLSResult décrit le handshake et la validation de la chaîne.
type TLSResult struct {
	Base
	Version             string     `json:"version"`
	Cipher              string     `json:"cipher"`
	ALPN                string     `json:"alpn,omitempty"`
	SNI                 string     `json:"sni,omitempty"`
	HandshakeMs         float64    `json:"handshake_ms"`
	Chain               []CertInfo `json:"chain,omitempty"`
	SystemOK            bool       `json:"system_ok"`
	SystemErr           string     `json:"system_err,omitempty"`
	MozillaOK           bool       `json:"mozilla_ok"`
	MozillaErr          string     `json:"mozilla_err,omitempty"`
	HostnameOK          bool       `json:"hostname_ok"`
	Expired             bool       `json:"expired,omitempty"`
	DaysLeft            int        `json:"days_left"`
	SelfSigned          bool       `json:"self_signed,omitempty"`
	MissingIntermediate bool       `json:"missing_intermediate,omitempty"`
	Weak                []string   `json:"weak,omitempty"`
	OCSPStapled         bool       `json:"ocsp_stapled"`
	Intercepted         bool       `json:"intercepted,omitempty"`
	InterceptIssuer     string     `json:"intercept_issuer,omitempty"`
	InterceptVendor     string     `json:"intercept_vendor,omitempty"`
	Via                 string     `json:"via,omitempty"` // direct, starttls
	Error               string     `json:"error,omitempty"`
}

// LeafSHA256 renvoie l'empreinte du certificat feuille.
func (t *TLSResult) LeafSHA256() string {
	if t == nil || len(t.Chain) == 0 {
		return ""
	}
	return t.Chain[0].SHA256
}

// ---------- HTTP ----------

// Timings décompose une requête façon curl -w.
type Timings struct {
	DNSMs   float64 `json:"dns_ms"`
	TCPMs   float64 `json:"tcp_ms"`
	TLSMs   float64 `json:"tls_ms"`
	TTFBMs  float64 `json:"ttfb_ms"`
	TotalMs float64 `json:"total_ms"`
}

// Redirect est une étape de la chaîne de redirection.
type Redirect struct {
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Location string `json:"location,omitempty"`
}

// HTTPResult décrit la couche HTTP 1.1 / 2.
type HTTPResult struct {
	Base
	URL          string     `json:"url"`
	Proto        string     `json:"proto,omitempty"`
	Code         int        `json:"code,omitempty"`
	Timings      Timings    `json:"timings"`
	Redirects    []Redirect `json:"redirects,omitempty"`
	FinalURL     string     `json:"final_url,omitempty"`
	Headers      []KV       `json:"headers,omitempty"`
	AltSvc       string     `json:"alt_svc,omitempty"`
	H3Advertised bool       `json:"h3_advertised"`
	H3Port       int        `json:"h3_port,omitempty"`
	Error        string     `json:"error,omitempty"`
	ErrorKind    string     `json:"error_kind,omitempty"` // timeout, reset, tls, other
}

// HTTP3Result décrit la tentative QUIC / HTTP/3.
type HTTP3Result struct {
	Base
	Attempted   bool    `json:"attempted"`
	Advertised  bool    `json:"advertised"`
	Port        int     `json:"port,omitempty"`
	OK          bool    `json:"ok"`
	Code        int     `json:"code,omitempty"`
	HandshakeMs float64 `json:"handshake_ms,omitempty"`
	TTFBMs      float64 `json:"ttfb_ms,omitempty"`
	TotalMs     float64 `json:"total_ms,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// ---------- Sondes par protocole ----------

// SSHInfo détaille la négociation SSH.
type SSHInfo struct {
	Version     string   `json:"version"`
	Kex         []string `json:"kex"`
	HostKeyAlgs []string `json:"host_key_algs"`
	Ciphers     []string `json:"ciphers"`
	MACs        []string `json:"macs"`
	Compression []string `json:"compression,omitempty"`
	Obsolete    []string `json:"obsolete,omitempty"`
	HostKeyType string   `json:"host_key_type,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
}

// RDPInfo détaille la négociation RDP.
type RDPInfo struct {
	Selected    string   `json:"selected"`
	Accepted    []string `json:"accepted"`
	NLARequired bool     `json:"nla_required"`
	Failure     string   `json:"failure,omitempty"`
}

// ProtoResult décrit la sonde applicative non-HTTP.
type ProtoResult struct {
	Base
	Proto        string   `json:"proto"`
	Banner       string   `json:"banner,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	TLSMode      string   `json:"tls_mode,omitempty"` // direct, starttls, none, unsupported
	TLSOffered   bool     `json:"tls_offered"`
	Info         []KV     `json:"info,omitempty"`
	SSH          *SSHInfo `json:"ssh,omitempty"`
	RDP          *RDPInfo `json:"rdp,omitempty"`
	Error        string   `json:"error,omitempty"`
}

// ---------- Traceroute ----------

// Hop est un saut du chemin.
type Hop struct {
	TTL      int      `json:"ttl"`
	Addr     string   `json:"addr,omitempty"`
	Others   []string `json:"others,omitempty"` // autres adresses vues (ECMP)
	Name     string   `json:"name,omitempty"`
	ASN      string   `json:"asn,omitempty"`
	Sent     int      `json:"sent"`
	Recv     int      `json:"recv"`
	LossPct  float64  `json:"loss_pct"`
	MinMs    float64  `json:"min_ms"`
	AvgMs    float64  `json:"avg_ms"`
	MaxMs    float64  `json:"max_ms"`
	JitterMs float64  `json:"jitter_ms"`
	Reached  bool     `json:"reached,omitempty"`
	Unreach  bool     `json:"unreachable,omitempty"`
	Silent   bool     `json:"silent,omitempty"`
}

// TraceResult est un traceroute dans un mode donné.
type TraceResult struct {
	Base
	Mode      string `json:"mode"` // icmp / tcp
	Method    string `json:"method,omitempty"`
	Dest      string `json:"dest"`
	Port      int    `json:"port,omitempty"`
	Hops      []Hop  `json:"hops,omitempty"`
	Reached   bool   `json:"reached"`
	LastHop   int    `json:"last_hop"`            // dernier saut ayant répondu
	LossFrom  int    `json:"loss_from,omitempty"` // saut où démarre une perte propagée
	Loop      bool   `json:"loop,omitempty"`
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
}

// ---------- Proxy transparent / portail captif ----------

// CaptiveCheck est une sonde de portail captif.
type CaptiveCheck struct {
	URL      string `json:"url"`
	Expected string `json:"expected"`
	Status   int    `json:"status,omitempty"`
	Location string `json:"location,omitempty"`
	Match    bool   `json:"match"`
	Error    string `json:"error,omitempty"`
	Headers  []KV   `json:"headers,omitempty"`
}

// CaptiveResult regroupe les sondes de portail captif et les heuristiques
// globales de proxy transparent.
type CaptiveResult struct {
	Base
	Checks           []CaptiveCheck `json:"checks"`
	Captive          string         `json:"captive"` // no, probable, check, unknown
	ProxyHeaders     []KV           `json:"proxy_headers,omitempty"`
	TestNetHTTP      []string       `json:"testnet_http,omitempty"` // IP non routables qui répondent
	TransparentProxy string         `json:"transparent_proxy"`      // no, probable, check
}

// ProxyResult regroupe les heuristiques de proxy transparent par cible.
type ProxyResult struct {
	Base
	Headers    []KV    `json:"headers,omitempty"`
	TCP80Ms    float64 `json:"tcp80_ms,omitempty"`
	ICMPMs     float64 `json:"icmp_ms,omitempty"`
	SynAckTTL  int     `json:"synack_ttl,omitempty"`
	SynAckHops int     `json:"synack_hops,omitempty"`
	TraceHops  int     `json:"trace_hops,omitempty"`
	Suspicion  string  `json:"suspicion"` // no, probable, check
}
