package journalview

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
)

type fixtureProvider struct {
	body     string
	reason   Reason
	err      error
	calls    int
	closed   bool
	closeErr error
	onClose  func()
	during   func(context.Context)
}

func (p *fixtureProvider) Open(ctx context.Context, q Query) (io.ReadCloser, Reason, error) {
	p.calls++
	if p.during != nil {
		p.during(ctx)
	}
	if p.err != nil {
		return nil, ReasonNone, p.err
	}
	return &fixtureCloser{Reader: strings.NewReader(p.body), close: func() error {
		p.closed = true
		if p.onClose != nil {
			p.onClose()
		}
		return p.closeErr
	}}, p.reason, nil
}

type fixtureCloser struct {
	io.Reader
	close func() error
}

func (c *fixtureCloser) Close() error { return c.close() }
func TestProviderStatusAndCleanup(t *testing.T) {
	q, now := fixtureQuery()
	for _, tc := range []struct {
		name, body string
		reason     Reason
		err        error
		want       Coverage
		wantReason Reason
	}{
		{"empty", "", ReasonNone, nil, Complete, ReasonNone},
		{"restricted empty", "", ReasonVisibilityRestricted, nil, Partial, ReasonVisibilityRestricted},
		{"restricted rows", fixtureLine(q, "safe fixture"), ReasonVisibilityRestricted, nil, Partial, ReasonVisibilityRestricted},
		{"bounded prefix", fixtureLine(q, "safe fixture") + "{", ReasonByteLimit, nil, Partial, ReasonByteLimit},
		{"denied", "", ReasonNone, SourceError{ReasonPermissionDenied}, Failed, ReasonPermissionDenied},
		{"missing", "", ReasonNone, SourceError{ReasonSourceMissing}, Failed, ReasonSourceMissing},
		{"raw failure", "", ReasonNone, errors.New("fixture diagnostic must disappear"), Failed, ReasonReadFailed},
		{"bad provider status", "", Reason("arbitrary"), nil, Failed, ReasonInvalidSource},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &fixtureProvider{body: tc.body, reason: tc.reason, err: tc.err}
			s, e := CollectWithProvider(context.Background(), q, now, p)
			if e != nil || s.Coverage != tc.want || s.Reason != tc.wantReason || s.CountExact != (tc.want == Complete) || p.calls != 1 || (tc.err == nil && !p.closed) {
				t.Fatal(s, e, p)
			}
			if _, e := Encode(s); e != nil {
				t.Fatal(e)
			}
		})
	}
	p := &fixtureProvider{body: fixtureLine(q, "safe"), reason: ReasonNone, closeErr: errors.New("fixture close failure")}
	s, e := CollectWithProvider(context.Background(), q, now, p)
	if e != nil || s.Coverage != Partial || s.Reason != ReasonReadFailed || !p.closed {
		t.Fatal(s, e)
	}
}
func TestInvalidAndCancelledNeverOpenProvider(t *testing.T) {
	q, now := fixtureQuery()
	p := &fixtureProvider{reason: ReasonNone}
	if _, e := CollectWithProvider(context.Background(), Query{}, now, p); e != ErrInvalidInput || p.calls != 0 {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, e := CollectWithProvider(ctx, q, now, p)
	if e != nil || s.Reason != ReasonTimeout || p.calls != 0 {
		t.Fatal(s, e)
	}
}
func TestAdmissionHeldSynchronouslyUntilCleanup(t *testing.T) {
	q, now := fixtureQuery()
	var slot atomic.Bool
	p := &fixtureProvider{reason: ReasonNone, during: func(ctx context.Context) {
		s, e := collectWith(ctx, q, now, &slot, func() (Provider, error) { t.Fatal("second provider constructed"); return nil, nil })
		if e != nil || s.Reason != ReasonCollectorBusy {
			t.Fatal(s, e)
		}
	}}
	s, e := collectWith(context.Background(), q, now, &slot, func() (Provider, error) { return p, nil })
	if e != nil || s.Coverage != Complete || !p.closed || slot.Load() {
		t.Fatal(s, e)
	}
}

func TestCleanupAfterFirstMessageExpansionKeepsValidPartial(t *testing.T) {
	q, now := fixtureQuery()
	for _, cancelAtClose := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		p := &fixtureProvider{body: fixtureLine(q, "token=x "+strings.Repeat("a", MaxMessageBytes-8)), reason: ReasonNone, closeErr: errors.New("fixture close failed")}
		if cancelAtClose {
			p.onClose = cancel
			p.closeErr = nil
		}
		s, e := CollectWithProvider(ctx, q, now, p)
		cancel()
		want := ReasonReadFailed
		if cancelAtClose {
			want = ReasonTimeout
		}
		if e != nil || s.Coverage != Partial || s.Reason != want || s.ObservedCount != 1 || len(s.Rows) != 0 {
			t.Fatal(s, e)
		}
		if _, e := Encode(s); e != nil {
			t.Fatal("invalid composed snapshot", e)
		}
	}
}
