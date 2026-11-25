//go:build live

package probe

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/target"
)

func dump(t *testing.T, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	t.Log(string(b))
}

func liveCfg(t *testing.T) Config {
	cfg := DefaultConfig()
	cfg.Env = Env(context.Background(), cfg)
	return cfg
}

func TestLiveEnv(t *testing.T) { dump(t, liveCfg(t).Env) }

func TestLiveDNS(t *testing.T) {
	cfg := liveCfg(t)
	h := os.Getenv("HOST")
	if h == "" {
		h = "www.google.com"
	}
	tg, _ := target.Parse(h, "")
	dump(t, DNS(context.Background(), cfg, tg))
	dump(t, DNSGlobal(context.Background(), cfg, tg.Host))
}

func TestLiveTCPProbe(t *testing.T) {
	cfg := liveCfg(t)
	l, err := newTCPICMPListener(cfg.Env.Priv, false)
	if err != nil {
		t.Skip(err)
	}
	p := &tcpProber{l: l, port: 443}
	dst := netip.MustParseAddr(os.Getenv("DST"))
	for i := 0; i < 6; i++ {
		for ttl := 1; ttl <= 4; ttl++ {
			r := p.Probe(context.Background(), dst, ttl, 2*time.Second)
			t.Logf("ttl=%d kind=%d from=%s rtt=%s", ttl, r.kind, r.from, r.rtt)
		}
	}
}
