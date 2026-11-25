package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// replyKind classe la réponse à une sonde.
type replyKind int

const (
	rTimeout      replyKind = iota // aucune réponse
	rTimeExceeded                  // TTL expiré en transit : saut intermédiaire
	rReached                       // destination atteinte (écho, SYN-ACK ou RST)
	rUnreachable                   // ICMP destination injoignable
)

// reply est la réponse à une sonde.
type reply struct {
	kind replyKind
	from netip.Addr
	rtt  time.Duration
	ttl  int // TTL / hop limit du paquet reçu (0 si inconnu)
	at   time.Time
}

// hopProber envoie une sonde avec un TTL donné et attend la réponse.
type hopProber interface {
	Probe(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) reply
	Close() error
}

var errNoICMP = errors.New("icmp indisponible")

// waitKey identifie une sonde en attente : 'e' = écho ICMP (seq),
// 't' = SYN TCP (port source).
type waitKey struct {
	kind byte
	n    int
}

// rawListener est une socket ICMP (raw ou datagramme) partagée, avec un
// lecteur qui répartit les réponses entre les sondes en attente.
type rawListener struct {
	v6    bool
	dgram bool
	pc    *icmp.PacketConn
	p4    *ipv4.PacketConn
	p6    *ipv6.PacketConn
	id    int
	seq   atomic.Uint32
	wmu   sync.Mutex
	mu    sync.Mutex
	wait  map[waitKey]chan reply
	done  chan struct{}
	close sync.Once
}

// newRawListener ouvre une socket ICMP. network : "ip4:icmp",
// "ip6:ipv6-icmp" (raw, droits requis) ou "udp4"/"udp6" (datagramme).
func newRawListener(network, laddr string) (*rawListener, error) {
	pc, err := icmp.ListenPacket(network, laddr)
	if err != nil {
		return nil, err
	}
	l := &rawListener{
		v6:    network == "ip6:ipv6-icmp" || network == "udp6",
		dgram: network == "udp4" || network == "udp6",
		pc:    pc,
		id:    rand.IntN(0xffff) + 1,
		wait:  map[waitKey]chan reply{},
		done:  make(chan struct{}),
	}
	l.seq.Store(uint32(rand.IntN(0x7fff)))
	if l.v6 {
		l.p6 = pc.IPv6PacketConn()
		if l.p6 != nil {
			_ = l.p6.SetControlMessage(ipv6.FlagHopLimit, true)
			if !l.dgram {
				var f ipv6.ICMPFilter
				f.SetAll(true)
				f.Accept(ipv6.ICMPTypeEchoReply)
				f.Accept(ipv6.ICMPTypeTimeExceeded)
				f.Accept(ipv6.ICMPTypeDestinationUnreachable)
				_ = l.p6.SetICMPFilter(&f)
			}
		}
	} else {
		l.p4 = pc.IPv4PacketConn()
		if l.p4 != nil {
			_ = l.p4.SetControlMessage(ipv4.FlagTTL, true)
		}
	}
	go l.readLoop()
	return l, nil
}

func (l *rawListener) Close() error {
	l.close.Do(func() { close(l.done); l.pc.Close() })
	return nil
}

func (l *rawListener) register(k waitKey) chan reply {
	ch := make(chan reply, 1)
	l.mu.Lock()
	l.wait[k] = ch
	l.mu.Unlock()
	return ch
}

func (l *rawListener) unregister(k waitKey) {
	l.mu.Lock()
	delete(l.wait, k)
	l.mu.Unlock()
}

func (l *rawListener) dispatch(k waitKey, r reply) {
	l.mu.Lock()
	ch := l.wait[k]
	l.mu.Unlock()
	if ch != nil {
		select {
		case ch <- r:
		default:
		}
	}
}

func (l *rawListener) readLoop() {
	buf := make([]byte, 1500)
	proto := 1
	if l.v6 {
		proto = 58
	}
	for {
		var (
			n   int
			src net.Addr
			ttl int
			err error
		)
		switch {
		case l.p4 != nil:
			var cm *ipv4.ControlMessage
			n, cm, src, err = l.p4.ReadFrom(buf)
			if cm != nil {
				ttl = cm.TTL
			}
		case l.p6 != nil:
			var cm *ipv6.ControlMessage
			n, cm, src, err = l.p6.ReadFrom(buf)
			if cm != nil {
				ttl = cm.HopLimit
			}
		default:
			n, src, err = l.pc.ReadFrom(buf)
		}
		at := time.Now()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		from := addrOf(src)
		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		switch b := msg.Body.(type) {
		case *icmp.Echo:
			if msg.Type == ipv4.ICMPTypeEchoReply || msg.Type == ipv6.ICMPTypeEchoReply {
				if l.dgram || b.ID == l.id {
					l.dispatch(waitKey{'e', b.Seq}, reply{kind: rReached, from: from, ttl: ttl, at: at})
				}
			}
		case *icmp.TimeExceeded:
			if k, ok := l.innerKey(b.Data); ok {
				l.dispatch(k, reply{kind: rTimeExceeded, from: from, ttl: ttl, at: at})
			}
		case *icmp.DstUnreach:
			if k, ok := l.innerKey(b.Data); ok {
				l.dispatch(k, reply{kind: rUnreachable, from: from, ttl: ttl, at: at})
			}
		}
	}
}

// innerKey extrait la clé de la sonde d'origine à partir du datagramme
// cité dans un message ICMP d'erreur.
func (l *rawListener) innerKey(data []byte) (waitKey, bool) {
	return parseInner(data, l.v6, l.id, l.dgram)
}

// parseInner analyse l'en-tête IP + 8 octets cités dans une erreur ICMP.
func parseInner(data []byte, v6 bool, id int, ignoreID bool) (waitKey, bool) {
	var proto int
	var inner []byte
	if !v6 {
		if len(data) < 20 || data[0]>>4 != 4 {
			return waitKey{}, false
		}
		ihl := int(data[0]&0x0f) * 4
		if len(data) < ihl+8 {
			return waitKey{}, false
		}
		proto = int(data[9])
		inner = data[ihl:]
	} else {
		if len(data) < 48 || data[0]>>4 != 6 {
			return waitKey{}, false
		}
		proto = int(data[6])
		inner = data[40:]
	}
	switch proto {
	case 1, 58: // ICMP / ICMPv6 echo
		if (proto == 1 && inner[0] != 8) || (proto == 58 && inner[0] != 128) {
			return waitKey{}, false
		}
		if !ignoreID && int(binary.BigEndian.Uint16(inner[4:6])) != id {
			return waitKey{}, false
		}
		return waitKey{'e', int(binary.BigEndian.Uint16(inner[6:8]))}, true
	case 6: // TCP : port source
		return waitKey{'t', int(binary.BigEndian.Uint16(inner[0:2]))}, true
	}
	return waitKey{}, false
}

func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.IPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}

// Probe envoie un écho ICMP avec le TTL donné.
func (l *rawListener) Probe(ctx context.Context, dst netip.Addr, ttl int, timeout time.Duration) reply {
	seq := int(l.seq.Add(1) & 0xffff)
	k := waitKey{'e', seq}
	ch := l.register(k)
	defer l.unregister(k)

	var typ icmp.Type = ipv4.ICMPTypeEcho
	if l.v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	msg := icmp.Message{Type: typ, Body: &icmp.Echo{ID: l.id, Seq: seq, Data: []byte("jalon-probe-0123456789")}}
	b, err := msg.Marshal(nil)
	if err != nil {
		return reply{kind: rTimeout}
	}
	var to net.Addr = &net.IPAddr{IP: dst.AsSlice()}
	if l.dgram {
		to = &net.UDPAddr{IP: dst.AsSlice()}
	}
	l.wmu.Lock()
	if l.v6 {
		if l.p6 != nil {
			_ = l.p6.SetHopLimit(ttl)
		}
	} else if l.p4 != nil {
		_ = l.p4.SetTTL(ttl)
	}
	start := time.Now()
	_, err = l.pc.WriteTo(b, to)
	l.wmu.Unlock()
	if err != nil {
		return reply{kind: rTimeout}
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-ch:
		r.rtt = r.at.Sub(start)
		return r
	case <-t.C:
	case <-ctx.Done():
	}
	return reply{kind: rTimeout}
}

// ping envoie count échos (TTL 64) et calcule les statistiques.
func ping(ctx context.Context, p hopProber, dst netip.Addr, count int, timeout time.Duration) (sent, recv int, rtts []time.Duration, ttl int) {
	for i := 0; i < count; i++ {
		if ctx.Err() != nil {
			break
		}
		sent++
		r := p.Probe(ctx, dst, 64, timeout)
		if r.kind == rReached {
			recv++
			rtts = append(rtts, r.rtt)
			if r.ttl > 0 {
				ttl = r.ttl
			}
		}
		if i < count-1 {
			select {
			case <-ctx.Done():
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	return
}
