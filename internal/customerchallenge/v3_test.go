package customerchallenge

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
)

type challengeMethods struct {
	name  string
	issue func(*Pool, int) (customerclaim.Context, error)
	take  func(*Pool, string) (customerclaim.Context, error)
}

var v3Methods = []challengeMethods{
	{"claim", func(p *Pool, n int) (customerclaim.Context, error) {
		return p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", n))
	}, (*Pool).Take},
	{"status", func(p *Pool, n int) (customerclaim.Context, error) {
		return p.IssueStatus("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", n))
	}, (*Pool).TakeStatus},
	{"credential-v3", func(p *Pool, n int) (customerclaim.Context, error) {
		return p.IssueCredentialV3("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", n))
	}, (*Pool).TakeCredentialV3},
	{"activation-v3", func(p *Pool, n int) (customerclaim.Context, error) {
		return p.IssueActivationV3("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", n))
	}, (*Pool).TakeActivationV3},
}

func TestV3PurposePairwiseSeparationAndBurn(t *testing.T) {
	for _, issueMethod := range v3Methods {
		for _, takeMethod := range v3Methods {
			t.Run(issueMethod.name+"/"+takeMethod.name, func(t *testing.T) {
				p, now := pool(t)
				c, err := issueMethod.issue(p, 1)
				if err != nil || !customerclaim.ValidChallengeContext(c, *now) {
					t.Fatal("issue", err)
				}
				got, err := takeMethod.take(p, c.Challenge)
				if issueMethod.name == takeMethod.name {
					if err != nil || got != c {
						t.Fatal("matching purpose failed", err)
					}
				} else if !errors.Is(err, ErrUnavailable) || got != (customerclaim.Context{}) {
					t.Fatal("wrong purpose disclosed context", err)
				}
				if _, err = issueMethod.take(p, c.Challenge); !errors.Is(err, ErrUnavailable) {
					t.Fatal("challenge replay/refund", err)
				}
			})
		}
	}
}

func TestV3PurposeConcurrentTakes(t *testing.T) {
	for _, method := range v3Methods[2:] {
		t.Run(method.name, func(t *testing.T) {
			p, _ := pool(t)
			c, err := method.issue(p, 1)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			results := make(chan error, 40)
			for i := 0; i < 40; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _, e := method.take(p, c.Challenge); results <- e }()
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
				t.Fatalf("got %d successful consumers", success)
			}
		})
	}
}

func TestV3ConcurrentDifferentPurposes(t *testing.T) {
	for _, expected := range v3Methods[2:] {
		t.Run(expected.name, func(t *testing.T) {
			p, _ := pool(t)
			c, err := expected.issue(p, 1)
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				name string
				err  error
			}
			var wg sync.WaitGroup
			results := make(chan result, 40)
			for n := 0; n < 40; n++ {
				method := v3Methods[n%len(v3Methods)]
				wg.Add(1)
				go func() { defer wg.Done(); _, e := method.take(p, c.Challenge); results <- result{method.name, e} }()
			}
			wg.Wait()
			close(results)
			success := 0
			for r := range results {
				if r.err == nil {
					if r.name != expected.name {
						t.Fatal("wrong purpose got context")
					}
					success++
				} else if !errors.Is(r.err, ErrUnavailable) {
					t.Fatal(r.err)
				}
			}
			if success > 1 {
				t.Fatal("multiple successful takes", success)
			}
			if _, err = expected.take(p, c.Challenge); !errors.Is(err, ErrUnavailable) {
				t.Fatal("nonce refunded", err)
			}
		})
	}
}

func TestV3ClockRegressionAndExpiry(t *testing.T) {
	for _, expected := range v3Methods[2:] {
		t.Run(expected.name, func(t *testing.T) {
			p, now := pool(t)
			c, err := expected.issue(p, 1)
			if err != nil {
				t.Fatal(err)
			}
			*now = now.Add(-time.Second)
			if _, err = expected.take(p, c.Challenge); !errors.Is(err, ErrClock) {
				t.Fatal("clock accepted", err)
			}
			*now = now.Add(time.Second)
			if _, err = expected.take(p, c.Challenge); err != nil {
				t.Fatal("same purpose did not recover", err)
			}
			c, err = expected.issue(p, 2)
			if err != nil {
				t.Fatal(err)
			}
			*now = now.Add(-time.Second)
			if _, err = p.Take(c.Challenge); !errors.Is(err, ErrClock) {
				t.Fatal("clock accepted wrong purpose", err)
			}
			*now = now.Add(time.Second)
			if _, err = expected.take(p, c.Challenge); !errors.Is(err, ErrUnavailable) {
				t.Fatal("wrong purpose refunded after rollback", err)
			}
			c, err = expected.issue(p, 3)
			if err != nil {
				t.Fatal(err)
			}
			*now = now.Add(time.Minute)
			if _, err = expected.take(p, c.Challenge); !errors.Is(err, ErrUnavailable) {
				t.Fatal("expired challenge accepted", err)
			}
		})
	}
}

func TestV3PurposeQuotaAndTombstonesAreShared(t *testing.T) {
	p, _ := pool(t)
	for n := 0; n < PerPeerPerMinute; n++ {
		if _, err := v3Methods[n%len(v3Methods)].issue(p, n+1); err != nil {
			t.Fatal(err)
		}
	}
	for _, method := range v3Methods {
		if _, err := method.issue(p, 99); !errors.Is(err, ErrBusy) {
			t.Fatal("shared quota bypass", method.name, err)
		}
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p, err := newPool(binding(), func() time.Time { return now }, bytes.NewReader(make([]byte, 96)))
	if err != nil {
		t.Fatal(err)
	}
	c, err := v3Methods[2].issue(p, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.TakeActivationV3(c.Challenge); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong purpose accepted", err)
	}
	if _, err = v3Methods[3].issue(p, 2); !errors.Is(err, ErrUnavailable) {
		t.Fatal("tombstone overwritten", err)
	}
	now = now.Add(time.Minute)
	if _, err = v3Methods[3].issue(p, 3); err != nil {
		t.Fatal("expired tombstone not reclaimed", err)
	}
}
