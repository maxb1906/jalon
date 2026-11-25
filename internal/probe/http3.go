package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/target"
)

func init() {
	// quic-go signale sur stderr l'impossibilité d'agrandir les tampons UDP :
	// sans intérêt pour un diagnostic ponctuel.
	_ = os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
}

// HTTP3 tente une requête HTTP/3 sur QUIC si Alt-Svc l'annonce (ou si
// demandé explicitement).
func HTTP3(ctx context.Context, cfg Config, t model.Target, ip string, advertised bool, port int) *model.HTTP3Result {
	start := time.Now()
	r := &model.HTTP3Result{Advertised: advertised, Port: port}
	defer r.Elapsed(start)
	if t.Proto != "https" {
		r.Skip("http3.not_https")
		return r
	}
	if !advertised && !cfg.ForceH3 {
		r.Skip("http3.not_advertised")
		return r
	}
	if port == 0 {
		port = t.Port
	}
	r.Port = port
	r.Attempted = true
	ctx, cancel := cfg.stepCtx(ctx)
	defer cancel()

	sni := t.Host
	if t.IsIP {
		sni = ""
	}
	var hsDur time.Duration
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: sni, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: cfg.timeout(), MaxIdleTimeout: cfg.timeout()},
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			dst := net.JoinHostPort(ip, strconv.Itoa(port))
			t0 := time.Now()
			c, err := quic.DialAddr(ctx, dst, tlsCfg, qc)
			hsDur = time.Since(t0)
			return c, err
		},
	}
	defer tr.Close()
	u := target.URL(t)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		r.Error = err.Error()
		r.Set(model.Fail, "http3.failed", r.Error)
		return r
	}
	req.Header.Set("User-Agent", UserAgent())
	t0 := time.Now()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		r.Error = shortErr(err)
		if advertised {
			r.Set(model.Warn, "http3.blocked", port, r.Error)
		} else {
			r.Set(model.Info, "http3.failed_forced", r.Error)
		}
		return r
	}
	r.TTFBMs = model.Ms(time.Since(t0))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512<<10))
	resp.Body.Close()
	r.TotalMs = model.Ms(time.Since(t0))
	r.HandshakeMs = model.Ms(hsDur)
	r.OK = true
	r.Code = resp.StatusCode
	r.Set(model.OK, "http3.ok", r.Code, ms1(r.HandshakeMs), ms1(r.TotalMs))
	if !advertised {
		r.AddNote(model.Info, "http3.forced_ok")
	}
	return r
}
