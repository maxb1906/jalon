package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/maxb1906/jalon/internal/model"
)

func TestBus(t *testing.T) {
	var b Bus
	var got []EventType
	b.Subscribe(func(e Event) { got = append(got, e.Type) })
	b.Emit(Event{Type: EvRunStart})
	b.Emit(Event{Type: EvRunDone})
	if len(got) != 2 || got[1] != EvRunDone {
		t.Error(got)
	}
	var nilBus *Bus
	nilBus.Emit(Event{}) // ne doit pas paniquer
}

func TestRunLocalHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	opt := DefaultOptions()
	opt.NoGlobal, opt.NoTrace = true, true
	opt.Probe.Timeout = time.Second
	var post int
	var mu sync.Mutex
	opt.PostTarget = func(*model.Report, *model.TargetReport) { mu.Lock(); post++; mu.Unlock() }
	e := New(opt)
	var events []EventType
	e.Bus.Subscribe(func(ev Event) { events = append(events, ev.Type) })
	targets := []model.Target{
		{Raw: "a", Host: "127.0.0.1", Port: port, Proto: "http", Path: "/", IsIP: true},
		{Raw: "b", Host: "127.0.0.1", Port: closed, Proto: "http", Path: "/", IsIP: true},
		{Raw: "c", Host: "127.0.0.1", Port: closed, Proto: "smtp", IsIP: true},
	}
	rep := e.Run(context.Background(), targets)
	if len(rep.Targets) != 3 || post != 3 {
		t.Fatalf("%d cibles, %d post", len(rep.Targets), post)
	}
	a, b, c := rep.Targets[0], rep.Targets[1], rep.Targets[2]
	if a.Verdict.Status != model.OK || a.HTTP == nil || a.HTTP.Code != 200 || a.ChosenIP != "127.0.0.1" {
		t.Errorf("a : %+v %+v", a.Verdict, a.HTTP)
	}
	if b.Verdict.Status != model.Fail || b.Verdict.Findings[0].Rule != "tcp_refused" || b.HTTP.Status != model.Skipped {
		t.Errorf("b : %+v", b.Verdict)
	}
	if c.Proto == nil || c.Proto.Status != model.Skipped {
		t.Errorf("c : %+v", c.Proto)
	}
	if rep.ExitCode != 2 {
		t.Errorf("exit %d", rep.ExitCode)
	}
	if events[0] != EvRunStart || events[len(events)-1] != EvRunDone {
		t.Errorf("événements %v", events)
	}
	_ = strconv.Itoa
}

func TestTraceModes(t *testing.T) {
	if m := traceModes("auto"); len(m) != 2 {
		t.Error(m)
	}
	if m := traceModes("tcp"); len(m) != 1 || m[0] != "tcp" {
		t.Error(m)
	}
}
