//go:build linux

package journalstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/journalrequest"
	"localrmm/internal/journalview"
)

var testNow = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
var testCurrent = Current{strings.Repeat("a", 64), "agent_" + strings.Repeat("b", 32), strings.Repeat("c", 64), "sha256:" + strings.Repeat("d", 64)}

func fixture(t *testing.T) (*State, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "journal")
	s, e := Initialize(context.Background(), dir, testCurrent.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}
func grant(t *testing.T, seq uint64) journalrequest.Grant {
	t.Helper()
	r, e := journalrequest.New(testCurrent.DeviceID, testCurrent.CertificateHash, seq, journalview.Query{Unit: "synthetic-private-unit.service", Start: testNow.Add(-time.Minute), End: testNow, MaxPriority: 5}, testNow)
	if e != nil {
		t.Fatal(e)
	}
	return journalrequest.Grant{Description: r.Description, PolicyDigest: testCurrent.PolicyDigest, ClaimedAt: testNow}
}
func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v; want %v", got, want)
	}
}
func consume(t *testing.T, s *State, g journalrequest.Grant) Permit {
	t.Helper()
	p, e := s.Consume(context.Background(), testCurrent, g, testNow)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func floor(t *testing.T, s *State, want uint64) {
	t.Helper()
	got, e := s.SequenceFloor()
	if e != nil || got != want {
		t.Fatalf("floor=%d err=%v want=%d", got, e, want)
	}
}
func read(t *testing.T, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func reopen(t *testing.T, dir string) *State {
	t.Helper()
	s, e := Open(context.Background(), dir, testCurrent.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestInitializeAndExistingOnly(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "absent")
	_, e := Open(ctx, dir, testCurrent.SenderBinding)
	wantErr(t, e, ErrCorrupt)
	if _, e = os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("Open created directory")
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	_, e = Open(ctx, dir, testCurrent.SenderBinding)
	wantErr(t, e, ErrCorrupt)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("Open changed empty directory")
	}
	s, e := Initialize(ctx, dir, testCurrent.SenderBinding)
	if e != nil {
		t.Fatal(e)
	}
	floor(t, s, 0)
	_, e = Open(ctx, dir, testCurrent.SenderBinding)
	wantErr(t, e, ErrLocked)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	raw := read(t, filepath.Join(dir, stateName))
	_, e = Initialize(ctx, dir, testCurrent.SenderBinding)
	wantErr(t, e, ErrUnsafe)
	if !bytes.Equal(raw, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("reinitialize changed state")
	}
	other := strings.Repeat("e", 64)
	_, e = Open(ctx, dir, other)
	wantErr(t, e, ErrBinding)
	s = reopen(t, dir)
	floor(t, s, 0)
	_ = s.Close()
	if e = os.Remove(filepath.Join(dir, stateName)); e != nil {
		t.Fatal(e)
	}
	_, e = Open(ctx, dir, testCurrent.SenderBinding)
	wantErr(t, e, ErrCorrupt)
	_, e = Initialize(ctx, dir, testCurrent.SenderBinding)
	wantErr(t, e, ErrUnsafe)
	if _, e = os.Stat(filepath.Join(dir, stateName)); !os.IsNotExist(e) {
		t.Fatal("missing state recreated")
	}
}
func TestServerGapsReplayAndRestart(t *testing.T) {
	s, dir := fixture(t)
	g := grant(t, 41)
	p := consume(t, s, g)
	floor(t, s, 41)
	copyState := *s
	copyPermit := p
	calls := 0
	call := func(_ context.Context, got journalrequest.Grant) error {
		calls++
		if got.Description.Identity != g.Description.Identity {
			t.Fatal("grant changed")
		}
		return nil
	}
	if e := copyState.Use(context.Background(), copyPermit, testCurrent, testNow, call); e != nil {
		t.Fatal(e)
	}
	wantErr(t, s.Use(context.Background(), p, testCurrent, testNow, call), ErrConsumed)
	_, e := copyState.Consume(context.Background(), testCurrent, g, testNow)
	wantErr(t, e, ErrConsumed)
	_, e = s.Consume(context.Background(), testCurrent, grant(t, 40), testNow)
	wantErr(t, e, ErrConsumed)
	newer := grant(t, 89)
	lost := consume(t, s, newer)
	floor(t, s, 89)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	restarted := reopen(t, dir)
	floor(t, restarted, 89)
	wantErr(t, restarted.Use(context.Background(), lost, testCurrent, testNow, call), ErrConsumed)
	_, e = restarted.Consume(context.Background(), testCurrent, newer, testNow)
	wantErr(t, e, ErrConsumed)
	_, e = restarted.Consume(context.Background(), testCurrent, g, testNow.Add(24*time.Hour))
	wantErr(t, e, ErrConsumed)
	floor(t, restarted, 89)
	if calls != 1 {
		t.Fatalf("helper calls=%d", calls)
	}
}
func TestConcurrentCopiedHandlesAndPermits(t *testing.T) {
	s, _ := fixture(t)
	g := grant(t, 700)
	var accepted atomic.Int32
	var calls atomic.Int32
	var wg sync.WaitGroup
	permits := make(chan Permit, 32)
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			copyState := *s
			p, e := copyState.Consume(context.Background(), testCurrent, g, testNow)
			if e == nil {
				accepted.Add(1)
				permits <- p
			} else if e != ErrConsumed {
				t.Errorf("consume: %v", e)
			}
		})
	}
	wg.Wait()
	close(permits)
	if accepted.Load() != 1 {
		t.Fatalf("admitted %d", accepted.Load())
	}
	p := <-permits
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			copyState := *s
			copyPermit := p
			e := copyState.Use(context.Background(), copyPermit, testCurrent, testNow, func(context.Context, journalrequest.Grant) error { calls.Add(1); return nil })
			if e != nil && e != ErrConsumed {
				t.Errorf("Use: %v", e)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("invoked %d", calls.Load())
	}
	floor(t, s, 700)
}
func TestGrantValidationDoesNotAdvance(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Current, *journalrequest.Grant)
		want   error
	}{
		{"current-binding", func(c *Current, g *journalrequest.Grant) { c.SenderBinding = strings.Repeat("e", 64) }, ErrBinding},
		{"current-device", func(c *Current, g *journalrequest.Grant) { c.DeviceID = "agent_" + strings.Repeat("e", 32) }, ErrBinding},
		{"current-cert", func(c *Current, g *journalrequest.Grant) { c.CertificateHash = strings.Repeat("e", 64) }, ErrBinding},
		{"current-policy", func(c *Current, g *journalrequest.Grant) { c.PolicyDigest = "sha256:" + strings.Repeat("e", 64) }, ErrBinding},
		{"digest", func(c *Current, g *journalrequest.Grant) {
			g.Description.Identity.QueryDigest = "sha256:" + strings.Repeat("e", 64)
		}, ErrGrant},
		{"query", func(c *Current, g *journalrequest.Grant) { g.Description.Query.Unit = "changed.service" }, ErrGrant},
		{"budget", func(c *Current, g *journalrequest.Grant) { g.Description.Budgets.MaxRows++ }, ErrGrant},
		{"id", func(c *Current, g *journalrequest.Grant) { g.Description.Identity.ID = "bad" }, ErrGrant},
		{"sequence-zero", func(c *Current, g *journalrequest.Grant) { g.Description.Identity.Sequence = 0 }, ErrGrant},
		{"expiry-refresh", func(c *Current, g *journalrequest.Grant) {
			g.Description.ExpiresAt = g.Description.ExpiresAt.Add(time.Second)
		}, ErrGrant},
		{"claim-before-create", func(c *Current, g *journalrequest.Grant) { g.ClaimedAt = g.Description.CreatedAt.Add(-time.Second) }, ErrGrant},
		{"claim-after-expiry", func(c *Current, g *journalrequest.Grant) { g.ClaimedAt = g.Description.ExpiresAt }, ErrGrant},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, dir := fixture(t)
			before := read(t, filepath.Join(dir, stateName))
			g := grant(t, 80)
			c := testCurrent
			tt.change(&c, &g)
			p, e := s.Consume(context.Background(), c, g, testNow)
			wantErr(t, e, tt.want)
			if p.inner != nil {
				t.Fatal("invalid grant yielded permit")
			}
			floor(t, s, 0)
			if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
				t.Fatal("invalid grant advanced state")
			}
			// Expiry does not excuse malformed/foreign authority.
			_, e = s.Consume(context.Background(), c, g, testNow.Add(24*time.Hour))
			wantErr(t, e, tt.want)
			floor(t, s, 0)
		})
	}
}
func TestExpiredGrantLatchesAcrossClockReversalAndRestart(t *testing.T) {
	s, dir := fixture(t)
	g := grant(t, 903)
	p, e := s.Consume(context.Background(), testCurrent, g, g.Description.ExpiresAt)
	wantErr(t, e, ErrExpired)
	if p.inner != nil {
		t.Fatal("expired grant yielded permission")
	}
	floor(t, s, 903)
	retained, e := decodeRecord(read(t, filepath.Join(dir, stateName)))
	if e != nil {
		t.Fatal(e)
	}
	if retained.ExpiresAt != g.Description.ExpiresAt.Format(time.RFC3339Nano) || retained.QueryID != g.Description.Identity.ID || retained.QueryDigest != g.Description.Identity.QueryDigest || retained.PolicyDigest != g.PolicyDigest {
		t.Fatal("original metadata changed")
	}
	_, e = s.Consume(context.Background(), testCurrent, g, testNow)
	wantErr(t, e, ErrConsumed)
	_ = s.Close()
	s = reopen(t, dir)
	_, e = s.Consume(context.Background(), testCurrent, g, testNow)
	wantErr(t, e, ErrConsumed)
	floor(t, s, 903)
	consume(t, s, grant(t, 1000))
	floor(t, s, 1000)
}
func TestUseRevalidatesAndAlwaysConsumesPermit(t *testing.T) {
	for _, kind := range []string{"expiry", "binding", "policy", "canceled", "nil-callback", "callback-error", "panic", "newer-admission", "closed"} {
		t.Run(kind, func(t *testing.T) {
			s, _ := fixture(t)
			g := grant(t, 1)
			p := consume(t, s, g)
			copyPermit := p
			ctx := context.Background()
			current := testCurrent
			now := testNow
			calls := 0
			want := ErrConsumed
			invoke := func(context.Context, journalrequest.Grant) error { calls++; return nil }
			switch kind {
			case "expiry":
				now = g.Description.ExpiresAt
				want = ErrExpired
			case "binding":
				current.SenderBinding = strings.Repeat("e", 64)
				want = ErrBinding
			case "policy":
				current.PolicyDigest = "sha256:" + strings.Repeat("e", 64)
				want = ErrBinding
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = ErrCanceled
			case "nil-callback":
				invoke = nil
				want = ErrGrant
			case "callback-error":
				invoke = func(context.Context, journalrequest.Grant) error {
					calls++
					return errors.New("private helper content sentinel")
				}
				want = ErrHelper
			case "panic":
				invoke = func(context.Context, journalrequest.Grant) error { calls++; panic("synthetic panic") }
			case "newer-admission":
				consume(t, s, grant(t, 2))
			case "closed":
				_ = s.Close()
				want = ErrClosed
			}
			if kind == "panic" {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("panic missing")
						}
					}()
					_ = s.Use(ctx, p, current, now, invoke)
				}()
			} else {
				wantErr(t, s.Use(ctx, p, current, now, invoke), want)
			}
			retryErr := ErrConsumed
			if kind == "closed" {
				retryErr = ErrClosed
			}
			wantErr(t, s.Use(context.Background(), copyPermit, testCurrent, testNow, func(context.Context, journalrequest.Grant) error { t.Error("permission reused"); return nil }), retryErr)
			if (kind == "callback-error" || kind == "panic") && calls != 1 {
				t.Fatal("helper not attempted")
			}
		})
	}
}
func TestCancelBeforeMutationAndNoContentOnDisk(t *testing.T) {
	s, dir := fixture(t)
	g := grant(t, 1)
	before := read(t, filepath.Join(dir, stateName))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := s.Consume(ctx, testCurrent, g, testNow)
	wantErr(t, e, ErrCanceled)
	_, e = s.Consume(nil, testCurrent, g, testNow)
	wantErr(t, e, ErrCanceled)
	if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("canceled operation changed bytes")
	}
	floor(t, s, 0)
	absent := filepath.Join(t.TempDir(), "never")
	_, e = Initialize(ctx, absent, testCurrent.SenderBinding)
	wantErr(t, e, ErrCanceled)
	if _, e = os.Stat(absent); !os.IsNotExist(e) {
		t.Fatal("canceled initialize changed path")
	}
	p := consume(t, s, g)
	if e = s.Use(context.Background(), p, testCurrent, testNow, func(context.Context, journalrequest.Grant) error {
		_ = "synthetic log message SECRET_SENTINEL"
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 2 {
		t.Fatal("unexpected content file")
	}
	for _, entry := range entries {
		raw := read(t, filepath.Join(dir, entry.Name()))
		for _, forbidden := range []string{"SECRET_SENTINEL", g.Description.Query.Unit, "snapshot", "body", "message", "result"} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Fatal("content persisted")
			}
		}
		if len(raw) > MaxStateBytes {
			t.Fatal("metadata limit exceeded")
		}
	}
	for _, value := range []any{s, *s, p, &p, testCurrent, &testCurrent} {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			out := fmt.Sprintf(format, value)
			if !strings.Contains(out, "redacted") || strings.Contains(out, g.Description.Identity.ID) || strings.Contains(out, testCurrent.SenderBinding) {
				t.Fatal("format leaked metadata")
			}
		}
		raw, e := json.Marshal(value)
		if e != nil || string(raw) != `{"contentsRedacted":true}` {
			t.Fatal("JSON leaked metadata")
		}
	}
}
func TestZeroAndForeignPermit(t *testing.T) {
	s, _ := fixture(t)
	other, _ := fixture(t)
	p := consume(t, other, grant(t, 1))
	call := func(context.Context, journalrequest.Grant) error { t.Fatal("foreign helper invoked"); return nil }
	wantErr(t, s.Use(context.Background(), p, testCurrent, testNow, call), ErrConsumed)
	wantErr(t, s.Use(context.Background(), Permit{}, testCurrent, testNow, call), ErrConsumed)
	var zero State
	_, e := zero.SequenceFloor()
	wantErr(t, e, ErrClosed)
	if e = zero.Close(); e != nil {
		t.Fatal(e)
	}
}
