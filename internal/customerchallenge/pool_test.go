package customerchallenge

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
)

func binding() Binding {
	return Binding{ManagerID: "manager_" + strings.Repeat("1", 32), Origin: "https://manager.example:8443", AgentOrigin: "https://agent.example:8444", IssuerFingerprint: strings.Repeat("a", 64)}
}
func id(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }
func pool(t *testing.T) (*Pool, *time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p, e := New(binding(), func() time.Time { return now })
	if e != nil {
		t.Fatal(e)
	}
	return p, &now
}
func issue(t *testing.T, p *Pool) customerclaim.Context {
	t.Helper()
	c, e := p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 1))
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestIssueAndSingleConsumption(t *testing.T) {
	p, now := pool(t)
	c := issue(t, p)
	if c.ManagerID != binding().ManagerID || c.CustomerID != id("customer", 1) || c.InstallerProfileID != id("profile", 1) || c.Origin != binding().Origin || c.AgentOrigin != binding().AgentOrigin || c.IssuerFingerprint != binding().IssuerFingerprint || !customerclaim.ValidChallengeContext(c, *now) {
		t.Fatal("context binding invalid")
	}
	got, e := p.Take(c.Challenge)
	if e != nil || got != c {
		t.Fatal("take failed", e)
	}
	if _, e = p.Take(c.Challenge); !errors.Is(e, ErrUnavailable) {
		t.Fatal("replay accepted", e)
	}
	other := issue(t, p)
	if c.Challenge == other.Challenge {
		t.Fatal("random challenge repeated")
	}
	*now = now.Add(time.Minute)
	if _, e = p.Take(other.Challenge); !errors.Is(e, ErrUnavailable) {
		t.Fatal("expired challenge accepted", e)
	}
}

func TestCompetingConsumersOnlyOneSucceeds(t *testing.T) {
	p, _ := pool(t)
	c := issue(t, p)
	const n = 40
	var wg sync.WaitGroup
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := p.Take(c.Challenge); results <- e }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else if !errors.Is(e, ErrUnavailable) {
			t.Fatal(e)
		}
	}
	if success != 1 {
		t.Fatalf("%d successful consumers", success)
	}
}

func TestInvalidProofDoesNotRefundChallenge(t *testing.T) {
	p, now := pool(t)
	c := issue(t, p)
	trusted, err := p.Take(c.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = customerclaim.Verify([]byte(`{"bad":"proof"}`), trusted, *now); err == nil {
		t.Fatal("invalid proof accepted")
	}
	if _, err = p.Take(c.Challenge); !errors.Is(err, ErrUnavailable) {
		t.Fatal("failed proof refunded challenge", err)
	}
}

func TestRestartDoesNotRestoreChallengesOrLimits(t *testing.T) {
	p, now := pool(t)
	c := issue(t, p)
	newPool, e := New(binding(), func() time.Time { return *now })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = newPool.Take(c.Challenge); !errors.Is(e, ErrUnavailable) {
		t.Fatal("challenge survived restart", e)
	}
	if _, e = newPool.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 1)); e != nil {
		t.Fatal(e)
	}
}

func TestPeerCustomerAndGlobalLimits(t *testing.T) {
	t.Run("peer and mapped peer", func(t *testing.T) {
		p, now := pool(t)
		for i := 0; i < PerPeerPerMinute; i++ {
			if _, e := p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", i+1)); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := p.Issue("::ffff:192.0.2.1", id("customer", 2), id("profile", 1), id("claim", 99)); !errors.Is(e, ErrBusy) {
			t.Fatal("mapped peer bypass", e)
		}
		*now = now.Add(time.Minute)
		if _, e := p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 99)); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("customer", func(t *testing.T) {
		p, _ := pool(t)
		for i := 0; i < PerCustomerPerMinute; i++ {
			if _, e := p.Issue(fmt.Sprintf("192.0.2.%d", i+1), id("customer", 1), id("profile", 1), id("claim", i+1)); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := p.Issue("192.0.2.100", id("customer", 1), id("profile", 2), id("claim", 99)); !errors.Is(e, ErrBusy) {
			t.Fatal("customer bypass", e)
		}
	})
	t.Run("global", func(t *testing.T) {
		p, _ := pool(t)
		for i := 0; i < GlobalPerMinute; i++ {
			if _, e := p.Issue(fmt.Sprintf("192.0.2.%d", i+1), id("customer", i/30+1), id("profile", 1), id("claim", i+1)); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := p.Issue("192.0.2.200", id("customer", 5), id("profile", 1), id("claim", 200)); !errors.Is(e, ErrBusy) {
			t.Fatal("global limit bypass", e)
		}
	})
	t.Run("customer windows are bounded", func(t *testing.T) {
		p, now := pool(t)
		for i := 1; i <= MaxCustomers; i++ {
			if _, err := p.Issue(fmt.Sprintf("192.0.2.%d", i), id("customer", i), id("profile", 1), id("claim", i)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := p.Issue("192.0.2.26", id("customer", 26), id("profile", 1), id("claim", 26)); !errors.Is(err, ErrBusy) {
			t.Fatal("unbounded customer windows", err)
		}
		*now = now.Add(time.Minute)
		if _, err := p.Issue("192.0.2.26", id("customer", 26), id("profile", 1), id("claim", 26)); err != nil {
			t.Fatal("expired window not reclaimed", err)
		}
	})
}

func TestClockRollbackAndInvalidInputFailClosed(t *testing.T) {
	p, now := pool(t)
	c := issue(t, p)
	*now = now.Add(-time.Second)
	if _, e := p.Take(c.Challenge); !errors.Is(e, ErrClock) {
		t.Fatal("backward clock accepted", e)
	}
	if _, e := p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 2)); !errors.Is(e, ErrClock) {
		t.Fatal("backward issue accepted", e)
	}
	*now = now.Add(time.Second)
	if _, e := p.Take(c.Challenge); e != nil {
		t.Fatal("clock recovery lost unused challenge", e)
	}
	for _, peer := range []string{"hostname", "fe80::1%3", "192.0.2.1:443", ""} {
		if _, e := p.Issue(peer, id("customer", 1), id("profile", 1), id("claim", 1)); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid peer accepted", peer, e)
		}
	}
	if _, e := p.Issue("192.0.2.1", "customer_fake", id("profile", 1), id("claim", 1)); !errors.Is(e, ErrInvalid) {
		t.Fatal("invalid id accepted", e)
	}
	for _, v := range []string{"http://manager.example", "https://manager.example/?token=x", "https://USER@manager.example"} {
		b := binding()
		b.Origin = v
		if _, e := New(b, nil); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid TLS binding", v, e)
		}
	}
}

func TestEntropyFailureAndCollisionNeverOverwrite(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p, e := newPool(binding(), func() time.Time { return now }, bytes.NewReader(make([]byte, 64)))
	if e != nil {
		t.Fatal(e)
	}
	first := issue(t, p)
	if _, e = p.Issue("192.0.2.2", id("customer", 2), id("profile", 1), id("claim", 2)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("collision accepted", e)
	}
	if got, e := p.Take(first.Challenge); e != nil || got != first {
		t.Fatal("collision replaced existing context", e)
	}
	if _, e = p.Issue("192.0.2.3", id("customer", 3), id("profile", 1), id("claim", 3)); !errors.Is(e, ErrUnavailable) {
		t.Fatal("entropy failure accepted", e)
	}
}

func TestConsumedNonceCannotBeReissuedBeforeItsExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p, err := newPool(binding(), func() time.Time { return now }, bytes.NewReader(make([]byte, 96)))
	if err != nil {
		t.Fatal(err)
	}
	c := issue(t, p)
	if _, err := p.Take(c.Challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Issue("192.0.2.2", id("customer", 1), id("profile", 1), id("claim", 1)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("consumed challenge was reissued", err)
	}
	if _, err := p.Take(c.Challenge); !errors.Is(err, ErrUnavailable) {
		t.Fatal("consumed nonce reused", err)
	}
	now = now.Add(time.Minute)
	if _, err := p.Issue("192.0.2.2", id("customer", 1), id("profile", 1), id("claim", 1)); err != nil {
		t.Fatal("expired tombstone not reclaimed", err)
	}
}

func TestZeroPoolFailsClosed(t *testing.T) {
	var p Pool
	if _, err := p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 1)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := p.Take(strings.Repeat("a", 43)); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}
