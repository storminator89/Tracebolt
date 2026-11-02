//go:build linux

package main

import (
	"context"
	"io"
	"localrmm/internal/lanstore"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestManagerRequestDrainSharedAdmissionAndPanic(t *testing.T) {
	drain := newManagerRequestDrain()
	started := make(chan struct{}, 2)
	operatorEnd, agentEnd := make(chan struct{}), make(chan struct{})
	var operatorOnce, agentOnce sync.Once
	releaseOperator := func() { operatorOnce.Do(func() { close(operatorEnd) }) }
	releaseAgent := func() { agentOnce.Do(func() { close(agentEnd) }) }
	defer releaseOperator()
	defer releaseAgent()
	var completed sync.WaitGroup
	for _, end := range []chan struct{}{operatorEnd, agentEnd} {
		end := end
		handler := drain.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { started <- struct{}{}; <-end }))
		completed.Add(1)
		go func() {
			defer completed.Done()
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("synthetic request did not start")
		}
	}
	drain.Stop()
	drain.Stop()
	late := httptest.NewRecorder()
	drain.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("late handler admitted") })).ServeHTTP(late, httptest.NewRequest(http.MethodPost, "/", nil))
	if late.Code != http.StatusServiceUnavailable || late.Header().Get("Cache-Control") != "no-store" || drain.Drained() {
		t.Fatal("drain admission/active truth incorrect")
	}
	closed := make(chan struct{})
	drain.CloseAfterDrain(func() { close(closed) })
	releaseOperator()
	select {
	case <-closed:
		t.Fatal("state closed while endpoint handler still owned it")
	default:
	}
	releaseAgent()
	completed.Wait()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("completed handlers did not release state")
	}
	// A panic still relinquishes handler ownership; the gate never swallows it.
	panicking := newManagerRequestDrain()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("handler panic was swallowed")
			}
		}()
		panicking.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("synthetic handler panic") })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	panicking.Stop()
	if !panicking.Drained() {
		t.Fatal("panic retained an active handler")
	}
}

func TestManagerRequestDrainTimeoutRetainsLeaseWithoutBlockingRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-state")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	lease, err := lanstore.AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	drain := newManagerRequestDrain()
	started := make(chan struct{})
	blocked := make(chan struct{})
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(blocked) }) }
	defer unblock()
	lastWrite := make(chan struct{})
	operator := httptest.NewServer(drain.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		// Deliberately ignore connection/context cancellation, as a slow local
		// settings commit could. No cleanup may race the remaining owned work.
		<-blocked
		close(lastWrite)
		_, _ = io.WriteString(w, "synthetic completion")
	})))
	defer operator.Close()
	agent := httptest.NewServer(drain.Wrap(http.NotFoundHandler()))
	defer agent.Close()
	// Unblock owned work before httptest.Close even on an assertion failure.
	defer unblock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, operator.URL, nil)
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("synthetic loopback request did not start")
	}
	begin := time.Now()
	if err := stopManagerHTTP(operator.Config, agent.Config, drain, 20*time.Millisecond); err != errManagerHTTPDrainIncomplete {
		t.Fatal("unfinished handler was reported as a clean shutdown", err)
	}
	if time.Since(begin) > 2*time.Second {
		t.Fatal("shutdown added an unbounded handler join")
	}
	cleaned := make(chan struct{})
	drain.CloseAfterDrain(func() {
		select {
		case <-lastWrite:
		default:
			t.Error("state cleanup preceded final handler work")
		}
		_ = lease.Close()
		close(cleaned)
	})
	drain.CloseAfterDrain(func() { t.Error("cleanup scheduled more than once") })
	if other, err := lanstore.AcquireManagerWriter(dir); err != lanstore.ErrManagerWriterBusy || other != nil {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("timed-out handler lost its writer ownership")
	}
	unblock()
	select {
	case <-cleaned:
	case <-ctx.Done():
		t.Fatal("handler completion did not finish deferred cleanup")
	}
	other, err := lanstore.AcquireManagerWriter(dir)
	if err != nil {
		t.Fatal("completed cleanup retained ownership")
	}
	_ = other.Close()
	select {
	case <-clientDone:
	case <-ctx.Done():
		t.Fatal("forced connection close did not settle client")
	}
}

func TestManagerRequestDrainCleanStopCleansSynchronously(t *testing.T) {
	drain := newManagerRequestDrain()
	operator, agent := &http.Server{}, &http.Server{}
	if err := stopManagerHTTP(operator, agent, drain, time.Second); err != nil {
		t.Fatal(err)
	}
	closed := false
	drain.CloseAfterDrain(func() { closed = true })
	if !closed {
		t.Fatal("fully drained state was not closed synchronously")
	}
}
