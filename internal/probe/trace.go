package probe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/maxb1906/jalon/internal/model"
)

// IsV6 indique si la chaîne est une adresse IPv6.
func IsV6(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is6() && !a.Is4In6()
}

// hopAgg agrège les sondes d'un saut.
type hopAgg struct {
	sent, recv int
	rtts       []float64
	addrs      map[string]int
	reached    bool
	reachedN   int
	unreach    bool
}

// tracer exécute un traceroute façon MTR.
type tracer struct {
	cfg     Config
	mode    string
	dst     netip.Addr
	port    int
	prober  hopProber
	method  string
	mu      sync.Mutex
	hops    []*hopAgg
	destTTL int
}

// Trace exécute un traceroute (ICMP ou TCP SYN) vers dest. onUpdate reçoit
// un instantané après chaque tour.
func Trace(ctx context.Context, cfg Config, mode, dest string, port int, onUpdate func(*model.TraceResult)) *model.TraceResult {
	return TraceRounds(ctx, cfg, mode, dest, port, cfg.TraceProbes, onUpdate)
}

// TraceRounds est Trace avec un nombre de tours explicite (<= 0 : jusqu'à
// l'annulation du contexte, pour le MTR live).
func TraceRounds(ctx context.Context, cfg Config, mode, dest string, port int, rounds int, onUpdate func(*model.TraceResult)) *model.TraceResult {
	start := time.Now()
	r := &model.TraceResult{Mode: mode, Dest: dest}
	if mode == "tcp" {
		r.Port = port
	}
	defer r.Elapsed(start)
	dst, err := netip.ParseAddr(dest)
	if err != nil {
		r.Error = err.Error()
		r.Skip("trace.bad_dest", dest)
		return r
	}
	dst = dst.Unmap()
	priv := cfg.priv()
	var prober hopProber
	var method string
	switch mode {
	case "icmp":
		if !priv.ICMPTrace {
			r.Set(model.Skipped, priv.ICMPReason.Key)
			r.Summary = priv.ICMPReason
			return r
		}
		prober, method, err = newICMPProber(priv, dst.Is6())
	case "tcp":
		if !priv.TCPTrace {
			r.Status = model.Skipped
			r.Summary = priv.TCPReason
			return r
		}
		var l *rawListener
		l, err = newTCPICMPListener(priv, dst.Is6())
		if err == nil {
			prober, method = &tcpProber{l: l, port: port, v6: dst.Is6()}, priv.TCPMethod
		}
	default:
		err = fmt.Errorf("mode inconnu %q", mode)
	}
	if err != nil {
		r.Error = shortErr(err)
		r.Skip("trace.unavailable", r.Error)
		return r
	}
	defer prober.Close()
	r.Available, r.Method = true, method

	maxHops := cfg.MaxHops
	if maxHops <= 0 || maxHops > 64 {
		maxHops = 30
	}
	tc := &tracer{cfg: cfg, mode: mode, dst: dst, port: port, prober: prober, method: method}
	tc.hops = make([]*hopAgg, maxHops+1)
	for i := range tc.hops {
		tc.hops[i] = &hopAgg{addrs: map[string]int{}}
	}
	timeout := min(cfg.timeout(), 2*time.Second)
	for round := 0; rounds <= 0 || round < rounds; round++ {
		if ctx.Err() != nil {
			break
		}
		limit := maxHops
		if tc.destTTL > 0 {
			// Quelques sauts de plus : avec l'ECMP, la destination peut être
			// tantôt à N, tantôt à N+1 sauts.
			limit = min(maxHops, tc.destTTL+2)
		}
		var wg sync.WaitGroup
		for ttl := 1; ttl <= limit; ttl++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// Étaler légèrement les envois pour ne pas déclencher les
				// limitations ICMP des routeurs.
				time.Sleep(time.Duration(ttl) * 3 * time.Millisecond)
				rep := prober.Probe(ctx, dst, ttl, timeout)
				tc.record(ttl, rep)
			}()
		}
		wg.Wait()
		if onUpdate != nil {
			snap := tc.snapshot(r)
			onUpdate(snap)
		}
		if rounds <= 0 || round < rounds-1 {
			select {
			case <-ctx.Done():
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	final := tc.snapshot(r)
	*r = *final
	if !cfg.NoRDNS || cfg.ASN {
		enrichHops(ctx, cfg, r.Hops)
	}
	AnalyzeTrace(r)
	return r
}

func (tc *tracer) record(ttl int, rep reply) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	h := tc.hops[ttl]
	h.sent++
	if rep.kind == rTimeout {
		return
	}
	h.recv++
	h.rtts = append(h.rtts, model.Ms(rep.rtt))
	if rep.from.IsValid() {
		h.addrs[rep.from.String()]++
	}
	switch rep.kind {
	case rReached:
		h.reached = true
		h.reachedN++
		if tc.destTTL == 0 || ttl < tc.destTTL {
			tc.destTTL = ttl
		}
	case rUnreachable:
		h.unreach = true
		if rep.from == tc.dst {
			h.reached = true
			h.reachedN++
			if tc.destTTL == 0 || ttl < tc.destTTL {
				tc.destTTL = ttl
			}
		}
	}
}

// snapshot construit le résultat courant à partir des agrégats.
func (tc *tracer) snapshot(base *model.TraceResult) *model.TraceResult {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	r := *base
	r.Hops = nil
	last := 0
	for ttl := 1; ttl < len(tc.hops); ttl++ {
		if tc.hops[ttl].recv > 0 {
			last = ttl
		}
	}
	shown := min(len(tc.hops)-1, last+3)
	eff := tc.effectiveDest()
	if eff > 0 {
		shown = eff
	}
	for ttl := 1; ttl <= shown; ttl++ {
		h := tc.hops[ttl]
		if h.sent == 0 {
			continue
		}
		hop := model.Hop{TTL: ttl, Sent: h.sent, Recv: h.recv, Reached: ttl == eff, Unreach: h.unreach}
		hop.LossPct = math.Round(float64(h.sent-h.recv)/float64(h.sent)*1000) / 10
		type ac struct {
			a string
			n int
		}
		var al []ac
		for a, n := range h.addrs {
			al = append(al, ac{a, n})
		}
		slices.SortFunc(al, func(x, y ac) int {
			if x.n != y.n {
				return y.n - x.n
			}
			return strings.Compare(x.a, y.a)
		})
		for i, v := range al {
			if i == 0 {
				hop.Addr = v.a
			} else {
				hop.Others = append(hop.Others, v.a)
			}
		}
		if len(h.rtts) > 0 {
			mn, mx, sum := h.rtts[0], h.rtts[0], 0.0
			for _, v := range h.rtts {
				mn, mx = math.Min(mn, v), math.Max(mx, v)
				sum += v
			}
			hop.MinMs, hop.MaxMs = mn, mx
			hop.AvgMs = math.Round(sum/float64(len(h.rtts))*100) / 100
			if len(h.rtts) > 1 {
				var j float64
				for i := 1; i < len(h.rtts); i++ {
					j += math.Abs(h.rtts[i] - h.rtts[i-1])
				}
				hop.JitterMs = math.Round(j/float64(len(h.rtts)-1)*100) / 100
			}
		}
		r.Hops = append(r.Hops, hop)
	}
	r.Reached = eff > 0
	return &r
}

// effectiveDest choisit le saut de destination : le premier qui atteint la
// cible dans au moins 80 % des sondes, sinon celui qui l'atteint le plus
// souvent (chemins ECMP de longueurs différentes).
func (tc *tracer) effectiveDest() int {
	if tc.destTTL == 0 {
		return 0
	}
	best, bestRatio := tc.destTTL, -1.0
	for ttl := tc.destTTL; ttl < len(tc.hops) && ttl <= tc.destTTL+2; ttl++ {
		h := tc.hops[ttl]
		if h.sent == 0 {
			break
		}
		ratio := float64(h.reachedN) / float64(h.sent)
		if ratio >= 0.8 {
			return ttl
		}
		if ratio > bestRatio {
			best, bestRatio = ttl, ratio
		}
	}
	return best
}

// enrichHops ajoute la résolution inverse et, si demandé, l'ASN.
func enrichHops(ctx context.Context, cfg Config, hops []model.Hop) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range hops {
		if hops[i].Addr == "" {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !cfg.NoRDNS {
				if names, err := net.DefaultResolver.LookupAddr(ctx, hops[i].Addr); err == nil && len(names) > 0 {
					hops[i].Name = strings.TrimSuffix(names[0], ".")
				}
			}
			if cfg.ASN {
				hops[i].ASN = lookupASN(ctx, cfg, hops[i].Addr)
			}
		}()
	}
	wg.Wait()
}

// lookupASN interroge origin.asn.cymru.com (DNS TXT).
func lookupASN(ctx context.Context, cfg Config, ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return ""
	}
	rev, err := dns.ReverseAddr(a.String())
	if err != nil {
		return ""
	}
	zone := ".origin.asn.cymru.com"
	if a.Is6() {
		zone = ".origin6.asn.cymru.com"
		rev = strings.TrimSuffix(rev, ".ip6.arpa.")
	} else {
		rev = strings.TrimSuffix(rev, ".in-addr.arpa.")
	}
	m, _, _, err := dnsQuery(ctx, localServer(cfg), rev+zone, dns.TypeTXT, dns.ClassINET)
	if err != nil {
		return ""
	}
	if t := txtOf(m); t != "" {
		if f := strings.Split(t, "|"); len(f) > 0 {
			return "AS" + strings.Fields(strings.TrimSpace(f[0]))[0]
		}
	}
	return ""
}

// Seuil de perte significative (%).
const lossThreshold = 20.0

// AnalyzeTrace qualifie le chemin : destination atteinte, saut muet, boucle,
// perte propagée (vraie perte) ou isolée (limitation ICMP du routeur).
func AnalyzeTrace(r *model.TraceResult) {
	if !r.Available {
		return
	}
	r.LastHop, r.LossFrom, r.Loop = 0, 0, false
	r.Notes = nil
	for _, h := range r.Hops {
		if h.Recv > 0 {
			r.LastHop = h.TTL
		}
	}
	for i := range r.Hops {
		r.Hops[i].Silent = r.Hops[i].Recv == 0 && r.Hops[i].TTL < r.LastHop
	}
	// Boucle : même adresse qui revient après d'autres.
	seen := map[string]int{}
	var seq []string
	for _, h := range r.Hops {
		if h.Addr != "" && !h.Reached {
			seq = append(seq, h.Addr)
		}
	}
	for i, a := range seq {
		if j, ok := seen[a]; ok && i-j >= 2 {
			r.Loop = true
		}
		if _, ok := seen[a]; !ok {
			seen[a] = i
		}
	}
	// Perte propagée jusqu'à la destination.
	var dest *model.Hop
	for i := range r.Hops {
		if r.Hops[i].Reached {
			dest = &r.Hops[i]
			break
		}
	}
	var isolated, ecmp []string
	if dest != nil && dest.LossPct >= lossThreshold {
		from := dest.TTL
		for i := len(r.Hops) - 1; i >= 0; i-- {
			h := r.Hops[i]
			if h.TTL > dest.TTL {
				continue
			}
			if h.Recv == 0 && h.TTL != dest.TTL {
				continue // saut muet : n'indique rien
			}
			if h.LossPct >= lossThreshold/2 {
				from = h.TTL
			} else {
				break
			}
		}
		r.LossFrom = from
	}
	for _, h := range r.Hops {
		if h.Recv > 0 && h.LossPct >= lossThreshold && (r.LossFrom == 0 || h.TTL < r.LossFrom) && !h.Reached {
			if h.Addr == r.Dest {
				ecmp = append(ecmp, strconv.Itoa(h.TTL))
			} else {
				isolated = append(isolated, strconv.Itoa(h.TTL))
			}
		}
	}
	var silent []string
	for _, h := range r.Hops {
		if h.Silent {
			silent = append(silent, strconv.Itoa(h.TTL))
		}
	}
	lastAddr := ""
	for _, h := range r.Hops {
		if h.TTL == r.LastHop {
			lastAddr = hopLabel(h)
		}
	}
	switch {
	case r.Loop:
		r.Set(model.Fail, "trace.loop")
	case r.LastHop == 0:
		r.Set(model.Warn, "trace.no_response")
	case dest != nil && r.LossFrom > 0:
		r.Set(model.Warn, "trace.loss", dest.TTL, dest.LossPct, r.LossFrom)
	case dest != nil:
		r.Set(model.OK, "trace.ok", dest.TTL, ms1(dest.AvgMs))
	default:
		r.Set(model.Warn, "trace.not_reached", r.LastHop, lastAddr)
	}
	r.Reached = dest != nil
	if len(isolated) > 0 {
		r.AddNote(model.Info, "trace.isolated_loss", strings.Join(isolated, ", "))
	}
	if len(ecmp) > 0 {
		r.AddNote(model.Info, "trace.ecmp", strings.Join(ecmp, ", "))
	}
	if len(silent) > 0 {
		r.AddNote(model.Info, "trace.silent", strings.Join(silent, ", "))
	}
	if r.Method != "" {
		r.AddNote(model.Info, "trace.method", r.Method)
	}
}

func hopLabel(h model.Hop) string {
	if h.Name != "" {
		return h.Name + " (" + h.Addr + ")"
	}
	return h.Addr
}

// CompareTraces compare les chemins ICMP et TCP quand les deux ont tourné.
func CompareTraces(rs []*model.TraceResult) {
	var ic, tc *model.TraceResult
	for _, r := range rs {
		if r == nil || !r.Available {
			continue
		}
		switch r.Mode {
		case "icmp":
			ic = r
		case "tcp":
			tc = r
		}
	}
	if ic == nil || tc == nil {
		return
	}
	switch {
	case tc.Reached && !ic.Reached:
		ic.AddNote(model.Info, "trace.cmp_icmp_filtered")
		if ic.Status == model.Warn && ic.Summary.Key == "trace.not_reached" {
			ic.Status = model.Info
		}
	case ic.Reached && !tc.Reached:
		tc.AddNote(model.Warn, "trace.cmp_tcp_filtered", tc.LastHop)
	}
	a, b := addrSet(ic), addrSet(tc)
	if len(a) >= 2 && len(b) >= 2 {
		inter := 0
		for x := range a {
			if b[x] {
				inter++
			}
		}
		union := len(a) + len(b) - inter
		if float64(inter)/float64(union) < 0.5 {
			tc.AddNote(model.Info, "trace.cmp_paths_differ")
		}
	}
}

func addrSet(r *model.TraceResult) map[string]bool {
	m := map[string]bool{}
	for _, h := range r.Hops {
		if h.Addr != "" {
			m[h.Addr] = true
		}
	}
	return m
}

// ---------- TCP SYN par saut ----------

// tcpProber envoie un vrai SYN (connect() avec TTL réduit) et attend soit
// l'ICMP « TTL expiré » capté par la socket raw, soit la réponse de la
// destination (SYN-ACK ou RST).
type tcpProber struct {
	l    *rawListener
	port int
	v6   bool
}

func (p *tcpProber) Close() error { return p.l.Close() }

func (p *tcpProber) Probe(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) reply {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		lport := 33434 + rand.IntN(28000)
		k := waitKey{'t', lport}
		ch := p.l.register(k)
		r, err := p.try(ctx, dst, ttl, timeout, lport, ch)
		p.l.unregister(k)
		if err == nil {
			return r
		}
		lastErr = err
	}
	_ = lastErr
	return reply{kind: rTimeout}
}

var errAddrInUse = errors.New("port local occupé")

func (p *tcpProber) try(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration, lport int, ch chan reply) (reply, error) {
	network := "tcp4"
	if p.v6 {
		network = "tcp6"
	}
	d := &net.Dialer{
		LocalAddr: &net.TCPAddr{Port: lport},
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) { serr = setTTL(fd, ttl, p.v6) }); err != nil {
				return err
			}
			return serr
		},
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type res struct {
		c   net.Conn
		err error
		at  time.Time
	}
	done := make(chan res, 1)
	start := time.Now()
	go func() {
		c, err := d.DialContext(dctx, network, net.JoinHostPort(dst.String(), strconv.Itoa(p.port)))
		done <- res{c, err, time.Now()}
	}()
	select {
	case rep := <-ch:
		rep.rtt = rep.at.Sub(start)
		cancel()
		if x := <-done; x.c != nil {
			abort(x.c)
		}
		return rep, nil
	case x := <-done:
		if x.err == nil {
			abort(x.c)
			return reply{kind: rReached, from: dst, rtt: x.at.Sub(start)}, nil
		}
		switch classifyDialErr(x.err) {
		case tcpRefused:
			return reply{kind: rReached, from: dst, rtt: x.at.Sub(start)}, nil
		case tcpUnreachable:
			// L'ICMP correspondant est peut-être déjà dans le canal.
			select {
			case rep := <-ch:
				rep.rtt = rep.at.Sub(start)
				return rep, nil
			case <-time.After(50 * time.Millisecond):
			}
			return reply{kind: rUnreachable, rtt: x.at.Sub(start)}, nil
		}
		if isAddrInUse(x.err) {
			return reply{}, errAddrInUse
		}
		// Le délai est écoulé : un ICMP tardif a pu arriver.
		select {
		case rep := <-ch:
			rep.rtt = rep.at.Sub(start)
			return rep, nil
		default:
		}
		return reply{kind: rTimeout}, nil
	}
}

func abort(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	c.Close()
}
