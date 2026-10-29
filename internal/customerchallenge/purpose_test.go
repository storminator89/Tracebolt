package customerchallenge

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

func statusChallenge(t *testing.T, p *Pool) string {
	t.Helper()
	c, err := p.IssueStatus("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 1))
	if err != nil {
		t.Fatal(err)
	}
	return c.Challenge
}

func TestChallengePurposeSeparatesAndBurnsWrongTake(t *testing.T) {
	p, _ := pool(t)
	claim := issue(t, p)
	if _, err := p.TakeStatus(claim.Challenge); !errors.Is(err, ErrUnavailable) {
		t.Fatal("claim exposed as status", err)
	}
	if _, err := p.Take(claim.Challenge); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong-purpose claim attempt refunded", err)
	}
	status := statusChallenge(t, p)
	if _, err := p.Take(status); !errors.Is(err, ErrUnavailable) {
		t.Fatal("status exposed as claim", err)
	}
	if _, err := p.TakeStatus(status); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong-purpose status attempt refunded", err)
	}
	status = statusChallenge(t, p)
	if _, err := p.TakeStatus(status); err != nil {
		t.Fatal("matching status rejected", err)
	}
	if _, err := p.TakeStatus(status); !errors.Is(err, ErrUnavailable) {
		t.Fatal("status replay accepted", err)
	}
}

func TestWrongPurposeTombstoneCannotBeReissued(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	p, err := newPool(binding(), func() time.Time { return now }, bytes.NewReader(make([]byte, 96)))
	if err != nil {
		t.Fatal(err)
	}
	nonce := statusChallenge(t, p)
	if _, err = p.Take(nonce); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong purpose accepted", err)
	}
	if _, err = p.Issue("192.0.2.2", id("customer", 1), id("profile", 1), id("claim", 1)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nonce collision reused across purposes", err)
	}
	now = now.Add(time.Minute)
	if _, err = p.Issue("192.0.2.2", id("customer", 1), id("profile", 1), id("claim", 1)); err != nil {
		t.Fatal("expired tombstone not reclaimed", err)
	}
}

func TestConcurrentDifferentPurposeConsumersNeverExposeWrongContext(t *testing.T) {
	for _, statusPurpose := range []bool{false, true} {
		p, _ := pool(t)
		var nonce string
		if statusPurpose {
			nonce = statusChallenge(t, p)
		} else {
			nonce = issue(t, p).Challenge
		}
		type result struct {
			status bool
			err    error
		}
		results := make(chan result, 40)
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func(status bool) {
				defer wg.Done()
				var err error
				if status {
					_, err = p.TakeStatus(nonce)
				} else {
					_, err = p.Take(nonce)
				}
				results <- result{status, err}
			}(i%2 == 0)
		}
		wg.Wait()
		close(results)
		success := 0
		for r := range results {
			if r.err == nil {
				if r.status != statusPurpose {
					t.Fatal("wrong purpose obtained context")
				}
				success++
			} else if !errors.Is(r.err, ErrUnavailable) {
				t.Fatal(r.err)
			}
		}
		// A wrong-purpose consumer may win and burn the challenge; neither purpose
		// can succeed twice, and callers request a new one after such a loss.
		if success > 1 {
			t.Fatalf("%d successful takes", success)
		}
		if _, err := p.Take(nonce); !errors.Is(err, ErrUnavailable) {
			t.Fatal("challenge not consumed", err)
		}
		if _, err := p.TakeStatus(nonce); !errors.Is(err, ErrUnavailable) {
			t.Fatal("status challenge not consumed", err)
		}
	}
}

func TestPurposesSharePeerQuota(t *testing.T) {
	p, _ := pool(t)
	for i := 0; i < PerPeerPerMinute; i++ {
		var err error
		if i%2 == 0 {
			_, err = p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", i+1))
		} else {
			_, err = p.IssueStatus("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", i+1))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.IssueStatus("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 99)); !errors.Is(err, ErrBusy) {
		t.Fatal("purpose bypassed quota", err)
	}
	if _, err := p.Issue("192.0.2.1", id("customer", 1), id("profile", 1), id("claim", 99)); !errors.Is(err, ErrBusy) {
		t.Fatal("claim bypassed quota", err)
	}
}

func TestWrongPurposeWithClockRegressionIsStillConsumed(t *testing.T) {
	p, now := pool(t)
	status := statusChallenge(t, p)
	*now = now.Add(-time.Second)
	if _, err := p.Take(status); !errors.Is(err, ErrClock) {
		t.Fatal("clock failure not reported", err)
	}
	*now = now.Add(time.Second)
	if _, err := p.TakeStatus(status); !errors.Is(err, ErrUnavailable) {
		t.Fatal("wrong-purpose take refunded after clock recovery", err)
	}
}
