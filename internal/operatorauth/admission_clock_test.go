package operatorauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Observe the actual mutex wait before advancing the clock: sleeping alone could
// let the operation start only after expiry and miss the stale-clock regression.
func waitForAuthMutex(t *testing.T, method string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "operatorauth.(*Manager)."+method+"(") && strings.Contains(goroutine, "lockSlow(") {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("authentication operation did not reach the held manager mutex")
}

func TestLookupSamplesExpiryAfterManagerLock(t *testing.T) {
	for _, admitted := range []bool{false, true} {
		name := "idle"
		if admitted {
			name = "admitted_mutation"
		}
		t.Run(name, func(t *testing.T) {
			var ticks atomic.Int64
			start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			ticks.Store(start.UnixNano())
			m := fairnessManager(t, 2, func() time.Time { return time.Unix(0, ticks.Load()) })
			target := seedActorSession(m, 2, 1)
			delete(m.sessions, sha256.Sum256([]byte(target.ID)))
			token := strings.Repeat("a", 64)
			key, _ := tokenHash(token)
			m.sessions[key] = target
			release := func() {}
			if admitted {
				var err error
				release, err = target.BeginCapability(context.Background(), Read)
				if err != nil {
					t.Fatal(err)
				}
			}
			defer release()
			m.mu.Lock()
			locked := true
			defer func() {
				if locked {
					m.mu.Unlock()
				}
			}()
			done := make(chan error, 1)
			go func() { _, err := m.Lookup(token); done <- err }()
			waitForAuthMutex(t, "Lookup")
			ticks.Store(target.ExpiresAt.UnixNano())
			m.mu.Unlock()
			locked = false
			if err := <-done; !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("expired lookup admitted after mutex wait: %v", err)
			}
			if target.Lifetime().Err() == nil {
				t.Fatal("expiry did not cancel lifetime")
			}
			if len(m.sessions) != map[bool]int{false: 0, true: 1}[admitted] {
				t.Fatal("expiry broke admitted-work tombstone retention")
			}
			if next, err := target.BeginCapability(context.Background(), Read); err == nil {
				next()
				t.Fatal("expired copied session admitted")
			}
			release()
			if _, err := m.Lookup(token); !errors.Is(err, ErrUnauthenticated) || len(m.sessions) != 0 {
				t.Fatal("drained expiry tombstone retained")
			}
		})
	}
}

func TestAttemptSamplesWindowAfterManagerLock(t *testing.T) {
	var ticks atomic.Int64
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ticks.Store(start.UnixNano())
	m := fairnessManager(t, 2, func() time.Time { return time.Unix(0, ticks.Load()) })
	peer := netip.MustParseAddr("127.0.0.1")
	m.peers[peer] = attempts{start: start, count: 5}
	m.global = attempts{start: start, count: 30}
	m.mu.Lock()
	locked := true
	defer func() {
		if locked {
			m.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() { done <- m.attempt(peer.String()) }()
	waitForAuthMutex(t, "attempt")
	current := start.Add(time.Minute)
	ticks.Store(current.UnixNano())
	m.mu.Unlock()
	locked = false
	if err := <-done; err != nil {
		t.Fatalf("elapsed rate window used stale clock: %v", err)
	}
	if m.global.count != 1 || m.peers[peer].count != 1 || !m.global.start.Equal(current) || !m.peers[peer].start.Equal(current) {
		t.Fatal("rate window was backdated")
	}
}

type secondCheckContext struct {
	context.Context
	calls   int
	ready   chan struct{}
	proceed chan struct{}
}

func (c *secondCheckContext) Err() error {
	c.calls++
	if c.calls == 2 {
		close(c.ready)
		<-c.proceed
	}
	return c.Context.Err()
}

func TestLoginSamplesCapacityAndTTLAfterManagerLock(t *testing.T) {
	var ticks atomic.Int64
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ticks.Store(start.UnixNano())
	m := fairnessManager(t, 2, func() time.Time { return time.Unix(0, ticks.Load()) })
	for i := 1; i <= MaxSessionsPerActor; i++ {
		seedActorSession(m, 2, i)
	}
	ctx := &secondCheckContext{Context: context.Background(), ready: make(chan struct{}), proceed: make(chan struct{})}
	type result struct {
		session Session
		err     error
	}
	done := make(chan result, 1)
	go func() { s, err := m.LoginNamed(ctx, "127.0.0.1", "actor2", fixturePassword); done <- result{s, err} }()
	select {
	case <-ctx.ready:
	case <-time.After(10 * time.Second):
		t.Fatal("login did not finish password verification")
	}
	m.mu.Lock()
	locked := true
	defer func() {
		if locked {
			m.mu.Unlock()
		}
	}()
	close(ctx.proceed)
	waitForAuthMutex(t, "login")
	current := start.Add(DefaultTTL)
	ticks.Store(current.UnixNano())
	m.mu.Unlock()
	locked = false
	got := <-done
	if got.err != nil {
		t.Fatalf("expired quota retained after lock wait: %v", got.err)
	}
	if !got.session.ExpiresAt.Equal(current.Add(DefaultTTL)) || !got.session.gate.expires.Equal(got.session.ExpiresAt) {
		t.Fatal("new session TTL was backdated")
	}
	if len(m.sessions) != 1 {
		t.Fatal("expired quota not reclaimed")
	}
}

func TestRevokeSessionRechecksCancellationAfterManagerLock(t *testing.T) {
	m := fairnessManager(t, 2, nil)
	admin := seedActorSession(m, 1, 1)
	target := seedActorSession(m, 2, 1)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &secondCheckContext{Context: base, ready: make(chan struct{}), proceed: make(chan struct{})}
	type result struct {
		revoked bool
		err     error
	}
	done := make(chan result, 1)
	go func() { revoked, err := m.RevokeSession(ctx, admin, target.ID); done <- result{revoked, err} }()
	select {
	case <-ctx.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("requester did not reach admission")
	}
	m.mu.Lock()
	locked := true
	defer func() {
		if locked {
			m.mu.Unlock()
		}
	}()
	close(ctx.proceed)
	waitForAuthMutex(t, "RevokeSession")
	cancel()
	m.mu.Unlock()
	locked = false
	got := <-done
	if got.revoked || !errors.Is(got.err, ErrUnauthenticated) {
		t.Fatalf("cancelled request revoked target: revoked=%v err=%v", got.revoked, got.err)
	}
	if target.Lifetime().Err() != nil || target.gate.revoked.Load() || len(m.sessions) != 2 {
		t.Fatal("cancelled revoke modified target")
	}
	if ok, err := m.RevokeSession(context.Background(), admin, target.ID); err != nil || !ok {
		t.Fatal("fresh authorized revocation failed")
	}
}
