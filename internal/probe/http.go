package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/maxb1906/jalon/internal/model"
	"github.com/maxb1906/jalon/internal/target"
)

// En-têtes signalés dans le rapport.
var notableHeaders = []string{
	"Server", "Via", "X-Cache", "X-Cache-Hits", "X-Served-By", "X-Forwarded-For", "X-Proxy-Id",
	"Proxy-Connection", "Proxy-Agent", "X-Squid-Error", "X-BlueCoat-Via", "CF-Ray", "X-Amz-Cf-Id",
	"X-Akamai-Transformed", "Alt-Svc", "Strict-Transport-Security", "Location", "Content-Type",
	"X-Powered-By", "Age",
}

// Indices d'un proxy sur le chemin.
var proxyHeaders = []string{"Via", "X-Forwarded-For", "X-Proxy-Id", "Proxy-Connection", "Proxy-Agent", "X-Squid-Error", "X-BlueCoat-Via", "X-Cache"}

func pickHeaders(h http.Header, names []string) []model.KV {
	var out []model.KV
	for _, n := range names {
		if v := h.Values(n); len(v) > 0 {
			s := strings.Join(v, ", ")
			if len(s) > 200 {
				s = s[:200] + "…"
			}
			out = append(out, model.KV{Label: n, Value: s})
		}
	}
	// Tout en-tête Proxy-* inattendu.
	for k, v := range h {
		if strings.HasPrefix(k, "Proxy-") && !containsFold(names, k) {
			out = append(out, model.KV{Label: k, Value: strings.Join(v, ", ")})
		}
	}
	return out
}

func containsFold(l []string, s string) bool {
	for _, v := range l {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// parseAltSvc cherche une annonce h3 dans Alt-Svc et renvoie son port.
func parseAltSvc(v string, defPort int) (bool, int) {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		proto, rest, ok := strings.Cut(part, "=")
		if !ok || strings.TrimSpace(proto) != "h3" {
			continue
		}
		auth := strings.Trim(strings.SplitN(rest, ";", 2)[0], `" `)
		port := defPort
		if i := strings.LastIndex(auth, ":"); i >= 0 {
			if p, err := strconv.Atoi(auth[i+1:]); err == nil {
				port = p
			}
		}
		return true, port
	}
	return false, 0
}

func httpErrKind(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET) || strings.Contains(err.Error(), "reset by peer") || strings.Contains(err.Error(), "forcibly closed"):
		return "reset"
	case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused"):
		return "refused"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || strings.Contains(err.Error(), "EOF"):
		return "eof"
	case strings.Contains(err.Error(), "tls:"):
		return "tls"
	}
	return "other"
}

// HTTP interroge la cible en HTTP/1.1 ou HTTP/2 (ALPN), décompose les temps
// et suit les redirections.
func HTTP(ctx context.Context, cfg Config, t model.Target, ip string, dnsMs float64) *model.HTTPResult {
	start := time.Now()
	u := target.URL(t)
	r := &model.HTTPResult{URL: u}
	defer r.Elapsed(start)
	ctx, cancel := context.WithTimeout(ctx, 2*cfg.timeout())
	defer cancel()

	dialer := &net.Dialer{Timeout: cfg.timeout()}
	targetAddr := net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	tr := &http.Transport{
		Proxy: nil, // test en direct ; le proxy système est signalé à part
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == targetAddr && ip != "" {
				addr = net.JoinHostPort(ip, strconv.Itoa(t.Port))
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: true}, // chaîne analysée par l'étape TLS
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    cfg.timeout(),
		ResponseHeaderTimeout:  cfg.timeout(),
		DisableKeepAlives:      false,
		MaxResponseHeaderBytes: 1 << 20,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	cur := u
	var first *http.Response
	for hop := 0; hop < 10; hop++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, cur, nil)
		if err != nil {
			r.Error = err.Error()
			break
		}
		req.Header.Set("User-Agent", UserAgent())
		req.Header.Set("Accept", "*/*")
		var tm traceTimes
		if hop == 0 {
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), tm.trace()))
		}
		t0 := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			r.Error = shortErr(err)
			r.ErrorKind = httpErrKind(err)
			if hop == 0 {
				r.Timings = tm.timings(t0, dnsMs)
			}
			break
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512<<10))
		resp.Body.Close()
		if hop == 0 {
			first = resp
			r.Timings = tm.timings(t0, dnsMs)
			r.Timings.TotalMs = model.Ms(time.Since(t0)) + dnsMs
			r.Proto = resp.Proto
			r.Headers = pickHeaders(resp.Header, notableHeaders)
			r.AltSvc = resp.Header.Get("Alt-Svc")
			r.H3Advertised, r.H3Port = parseAltSvc(r.AltSvc, t.Port)
		}
		r.Code = resp.StatusCode
		r.FinalURL = cur
		loc := resp.Header.Get("Location")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && loc != "" {
			next, err := url.Parse(cur)
			if err == nil {
				if lu, err := next.Parse(loc); err == nil {
					r.Redirects = append(r.Redirects, model.Redirect{URL: cur, Status: resp.StatusCode, Location: lu.String()})
					cur = lu.String()
					continue
				}
			}
		}
		break
	}
	if len(r.Redirects) >= 10 {
		r.AddNote(model.Warn, "http.too_many_redirects")
	}

	switch {
	case first == nil:
		r.Set(model.Fail, "http.error_"+r.ErrorKind, r.Error)
	case r.Code >= 500:
		r.Set(model.Fail, "http.server_error", r.Code, r.FinalURL)
	case r.Code == 407:
		r.Set(model.Warn, "http.proxy_auth")
	case r.Code == 401:
		r.Set(model.OK, "http.auth_required", r.Code, r.Proto, ms1(r.Timings.TotalMs))
	case r.Code == 403 || r.Code == 451:
		r.Set(model.Warn, "http.forbidden", r.Code, r.FinalURL)
	case r.Code >= 400:
		r.Set(model.Warn, "http.client_error", r.Code, r.FinalURL)
	default:
		r.Set(model.OK, "http.ok", r.Code, r.Proto, ms1(r.Timings.TotalMs))
	}
	if first != nil {
		r.AddNote(model.Info, "http.timings", ms1(r.Timings.DNSMs), ms1(r.Timings.TCPMs), ms1(r.Timings.TLSMs), ms1(r.Timings.TTFBMs), ms1(r.Timings.TotalMs))
	}
	if len(r.Redirects) > 0 {
		r.AddNote(model.Info, "http.redirects", len(r.Redirects), r.FinalURL)
		if strings.HasPrefix(u, "https://") && strings.HasPrefix(r.FinalURL, "http://") {
			r.AddNote(model.Warn, "http.downgrade")
		}
	}
	if r.H3Advertised {
		r.AddNote(model.Info, "http.h3_advertised", r.H3Port)
	}
	if cfg.Env != nil && len(cfg.Env.Proxies) > 0 {
		r.AddNote(model.Info, "http.direct_note")
	}
	return r
}

// traceTimes collecte les instants clés d'une requête.
type traceTimes struct {
	connStart, connDone, tlsStart, tlsDone, firstByte time.Time
}

func (tm *traceTimes) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		ConnectStart:         func(string, string) { tm.connStart = time.Now() },
		ConnectDone:          func(string, string, error) { tm.connDone = time.Now() },
		TLSHandshakeStart:    func() { tm.tlsStart = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tm.tlsDone = time.Now() },
		GotFirstResponseByte: func() { tm.firstByte = time.Now() },
	}
}

func (tm *traceTimes) timings(t0 time.Time, dnsMs float64) model.Timings {
	t := model.Timings{DNSMs: dnsMs}
	if !tm.connStart.IsZero() && !tm.connDone.IsZero() {
		t.TCPMs = model.Ms(tm.connDone.Sub(tm.connStart))
	}
	if !tm.tlsStart.IsZero() && !tm.tlsDone.IsZero() {
		t.TLSMs = model.Ms(tm.tlsDone.Sub(tm.tlsStart))
	}
	if !tm.firstByte.IsZero() {
		t.TTFBMs = model.Ms(tm.firstByte.Sub(t0)) + dnsMs
	}
	return t
}
