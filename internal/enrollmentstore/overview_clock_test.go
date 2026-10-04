package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type overviewFixtureClock struct {
	nanos atomic.Int64
	calls atomic.Int64
}

func (c *overviewFixtureClock) set(t time.Time) { c.nanos.Store(t.UnixNano()) }
func (c *overviewFixtureClock) now() time.Time {
	c.calls.Add(1)
	return time.Unix(0, c.nanos.Load()).UTC()
}

// Hold the store's sole connection until the request is demonstrably queued.
// Advancing a controlled trusted clock never waits real minutes/hours.
func afterOverviewConnectionWait(t *testing.T, s *Store, advance func(), call func() error) error {
	t.Helper()
	held, e := s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	before := s.db.Stats().WaitCount
	done := make(chan error, 1)
	go func() { done <- call() }()
	deadline := time.Now().Add(3 * time.Second)
	for s.db.Stats().WaitCount == before {
		select {
		case e := <-done:
			t.Fatalf("request escaped held connection: %v", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("request did not queue for the held connection")
		}
		time.Sleep(time.Millisecond)
	}
	advance()
	if e = held.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		return e
	case <-time.After(3 * time.Second):
		t.Fatal("queued request did not finish")
		return nil
	}
}

func TestCompleteOverviewQueuedReadRechecksCursorAndCaptureExpiry(t *testing.T) {
	for _, kind := range []string{"cursor", "capture"} {
		t.Run(kind, func(t *testing.T) {
			_, s, _, snap, cert := overviewFixture(t)
			at := time.Unix(testNow+10, 0).UTC()
			capture := at
			if kind == "capture" {
				capture = at.Add(-23 * time.Hour)
			}
			b, m, c := overviewGeneration(t, snap.Approval.DeviceID, 1, 3, capture)
			promoteOverview(t, s, snap, cert, b, m, c, at)
			req := overviewledger.PageRequest{Section: "processes", GenerationID: b.GenerationID, Limit: 1}
			expiry := capture.Add(overviewledger.ObservationTTL)
			want := overviewledger.ErrExpired
			if kind == "cursor" {
				p, e := s.OverviewPage(context.Background(), snap.Approval.DeviceID, req, at)
				if e != nil {
					t.Fatal(e)
				}
				req.Cursor = p.NextCursor
				expiry = p.CursorExpiresAt
				want = overviewledger.ErrCursorExpired
			}
			initial := expiry.Add(-time.Nanosecond)
			clock := &overviewFixtureClock{}
			clock.set(initial)
			ctx := WithOverviewClock(context.Background(), clock.now)
			var got OverviewPageResult
			e := afterOverviewConnectionWait(t, s, func() {
				if clock.calls.Load() != 0 {
					t.Error("clock sampled before authority transaction")
				}
				clock.set(expiry)
			}, func() error {
				var err error
				got, err = s.OverviewPage(ctx, snap.Approval.DeviceID, req, initial)
				return err
			})
			if !errors.Is(e, want) || !reflect.DeepEqual(got, OverviewPageResult{}) {
				t.Fatal("expired queued page exposed data", e)
			}
		})
	}
}

func TestCompleteOverviewQueuedActionsRecheckCertificateExpiry(t *testing.T) {
	for _, operation := range []string{"begin", "append", "finalize", "abort", "failure", "status", "view", "page"} {
		t.Run(operation, func(t *testing.T) {
			_, s, _, snap, cert := overviewFixture(t)
			expiry := time.Unix(snap.Intent.NotAfter, 0).UTC()
			at := expiry.Add(-time.Minute)
			b, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 3, at)
			promoteOverview(t, s, snap, cert, b, m, chunks, at)
			initial := expiry.Add(-time.Nanosecond)
			clock := &overviewFixtureClock{}
			clock.set(initial)
			ctx := WithOverviewClock(context.Background(), clock.now)
			call := func() error {
				switch operation {
				case "begin":
					out, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, initial)
					if e != nil && !reflect.DeepEqual(out, overviewledger.BeginReceipt{}) {
						t.Error("provisional begin escaped")
					}
					return e
				case "append":
					out, e := s.OverviewAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, chunks[0], initial)
					if e != nil && !reflect.DeepEqual(out, overviewledger.ChunkReceipt{}) {
						t.Error("provisional append escaped")
					}
					return e
				case "finalize":
					out, e := s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, initial)
					if e != nil && !reflect.DeepEqual(out, overviewledger.Completion{}) {
						t.Error("provisional finalize escaped")
					}
					return e
				case "abort":
					return s.OverviewAbort(ctx, snap.InvitationID, cert.CertificateHash(), b, initial)
				case "failure":
					id, _ := overviewwire.GenerationID(snap.Approval.DeviceID, "processes", 2)
					out, e := s.OverviewFailure(ctx, snap.InvitationID, cert.CertificateHash(), OverviewFailureReport{Section: "processes", Sequence: 2, GenerationID: id, AttemptedAt: initial, Reason: "timeout"}, initial)
					if e != nil && !reflect.DeepEqual(out, OverviewFailureReceipt{}) {
						t.Error("provisional failure escaped")
					}
					return e
				case "status":
					out, e := s.OverviewStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, initial)
					if e != nil && !reflect.DeepEqual(out, OverviewSectionStatus{}) {
						t.Error("provisional status escaped")
					}
					return e
				case "view":
					out, e := s.OverviewView(ctx, snap.Approval.DeviceID, initial)
					if e != nil && !reflect.DeepEqual(out, OverviewStatus{}) {
						t.Error("provisional view escaped")
					}
					return e
				default:
					out, e := s.OverviewPage(ctx, snap.Approval.DeviceID, overviewledger.PageRequest{Section: "processes", GenerationID: b.GenerationID, Limit: 1}, initial)
					if e != nil && !reflect.DeepEqual(out, OverviewPageResult{}) {
						t.Error("provisional page escaped")
					}
					return e
				}
			}
			if e := afterOverviewConnectionWait(t, s, func() { clock.set(expiry) }, call); !errors.Is(e, enrollmentstate.ErrExpired) {
				t.Fatal("stale current certificate admitted queued operation", e)
			}
		})
	}
}

func TestCompleteOverviewQueuedStagingCannotPromoteOrAppendAfterExpiry(t *testing.T) {
	for _, operation := range []string{"begin", "append", "finalize", "status"} {
		t.Run(operation, func(t *testing.T) {
			_, s, _, snap, cert := overviewFixture(t)
			at := time.Unix(testNow+10, 0).UTC()
			b, m, chunks := overviewGeneration(t, snap.Approval.DeviceID, 1, 129, at)
			if _, e := s.OverviewBegin(context.Background(), snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
				t.Fatal(e)
			}
			if operation == "finalize" {
				for _, c := range chunks {
					if _, e := s.OverviewAppend(context.Background(), snap.InvitationID, cert.CertificateHash(), b, c, at); e != nil {
						t.Fatal(e)
					}
				}
			}
			expiry := at.Add(overviewledger.StagingTTL)
			initial := expiry.Add(-time.Nanosecond)
			clock := &overviewFixtureClock{}
			clock.set(initial)
			ctx := WithOverviewClock(context.Background(), clock.now)
			var status OverviewSectionStatus
			e := afterOverviewConnectionWait(t, s, func() { clock.set(expiry) }, func() error {
				switch operation {
				case "begin":
					_, e := s.OverviewBegin(ctx, snap.InvitationID, cert.CertificateHash(), b, m, initial)
					return e
				case "append":
					_, e := s.OverviewAppend(ctx, snap.InvitationID, cert.CertificateHash(), b, chunks[0], initial)
					return e
				case "finalize":
					_, e := s.OverviewFinalize(ctx, snap.InvitationID, cert.CertificateHash(), b, initial)
					return e
				default:
					var e error
					status, e = s.OverviewStatus(ctx, snap.InvitationID, cert.CertificateHash(), b, initial)
					return e
				}
			})
			if operation == "status" {
				if e != nil || status.Transfer == nil || status.Transfer.State != "expired" || !status.ServerNow.Equal(expiry) {
					t.Fatal("stale pending state escaped", e)
				}
			} else if !errors.Is(e, overviewledger.ErrExpired) {
				t.Fatal("expired staging operation accepted", e)
			}
			var current string
			if s.db.QueryRow(`SELECT current_generation FROM co_devices WHERE device=?`, overviewDevice(snap.Approval.DeviceID, "processes")).Scan(&current) != nil || current != "" {
				t.Fatal("expired staging promoted")
			}
		})
	}
}

func TestCompleteOverviewPostCommitBoundaryAndClockRollback(t *testing.T) {
	_, s, _, snap, cert := overviewFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	b, m, c := overviewGeneration(t, snap.Approval.DeviceID, 1, 3, at)
	promoteOverview(t, s, snap, cert, b, m, c, at)
	req := overviewledger.PageRequest{Section: "processes", GenerationID: b.GenerationID, Limit: 1}
	first, e := s.OverviewPage(context.Background(), snap.Approval.DeviceID, req, at)
	if e != nil {
		t.Fatal(e)
	}
	req.Cursor = first.NextCursor
	expiry := first.CursorExpiresAt
	initial := expiry.Add(-time.Nanosecond)
	var calls atomic.Int64
	ctx := WithOverviewClock(context.Background(), func() time.Time {
		if calls.Add(1) == 1 {
			return initial
		}
		return expiry
	})
	out, e := s.OverviewPage(ctx, snap.Approval.DeviceID, req, initial)
	if !errors.Is(e, overviewledger.ErrCursorExpired) || !reflect.DeepEqual(out, OverviewPageResult{}) {
		t.Fatal("post-COMMIT expired page escaped", e)
	}
	// A trusted clock moving backward within the request cannot revive a cursor
	// that was already expired at the caller's initial trusted sample.
	ctx = WithOverviewClock(context.Background(), func() time.Time { return at })
	out, e = s.OverviewPage(ctx, snap.Approval.DeviceID, req, expiry)
	if !errors.Is(e, overviewledger.ErrCursorExpired) || !reflect.DeepEqual(out, OverviewPageResult{}) {
		t.Fatal("clock rollback revived expired cursor", e)
	}
}

func TestCompleteOverviewQueuedBeginImmediateUsesFreshClock(t *testing.T) {
	f, s, path, snap, cert := overviewFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	b, m, c := overviewGeneration(t, snap.Approval.DeviceID, 1, 3, at)
	promoteOverview(t, s, snap, cert, b, m, c, at)
	req := overviewledger.PageRequest{Section: "processes", GenerationID: b.GenerationID, Limit: 1}
	page, e := s.OverviewPage(context.Background(), snap.Approval.DeviceID, req, at)
	if e != nil {
		t.Fatal(e)
	}
	req.Cursor = page.NextCursor
	other := f.open(t, path)
	held, e := other.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	if _, e = held.ExecContext(context.Background(), "BEGIN IMMEDIATE"); e != nil {
		t.Fatal(e)
	}
	defer held.ExecContext(context.Background(), "ROLLBACK")
	initial := page.CursorExpiresAt.Add(-time.Nanosecond)
	clock := &overviewFixtureClock{}
	clock.set(initial)
	ctx := WithOverviewClock(context.Background(), clock.now)
	done := make(chan error, 1)
	var out OverviewPageResult
	go func() { var e error; out, e = s.OverviewPage(ctx, snap.Approval.DeviceID, req, initial); done <- e }()
	deadline := time.Now().Add(3 * time.Second)
	for s.db.Stats().InUse == 0 {
		if time.Now().After(deadline) {
			t.Fatal("request did not acquire its connection")
		}
		time.Sleep(time.Millisecond)
	}
	if clock.calls.Load() != 0 {
		t.Fatal("clock sampled before acquiring writer transaction")
	}
	clock.set(page.CursorExpiresAt)
	if _, e = held.ExecContext(context.Background(), "ROLLBACK"); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if !errors.Is(e, overviewledger.ErrCursorExpired) || !reflect.DeepEqual(out, OverviewPageResult{}) {
			t.Fatal("writer wait revived expired cursor", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer wait did not finish")
	}
}

func TestCompleteOverviewPostCommitGETRejectsStaleLabels(t *testing.T) {
	for _, state := range []string{"pending", "complete"} {
		t.Run(state, func(t *testing.T) {
			_, s, _, snap, cert := overviewFixture(t)
			at := time.Unix(testNow+10, 0).UTC()
			capture := at
			if state == "complete" {
				capture = at.Add(-23 * time.Hour)
			}
			b, m, c := overviewGeneration(t, snap.Approval.DeviceID, 1, 3, capture)
			expiry := at.Add(overviewledger.StagingTTL)
			if state == "complete" {
				promoteOverview(t, s, snap, cert, b, m, c, at)
				expiry = capture.Add(overviewledger.ObservationTTL)
			} else {
				if _, e := s.OverviewBegin(context.Background(), snap.InvitationID, cert.CertificateHash(), b, m, at); e != nil {
					t.Fatal(e)
				}
			}
			initial := expiry.Add(-time.Nanosecond)
			var calls atomic.Int64
			ctx := WithOverviewClock(context.Background(), func() time.Time {
				if calls.Add(1) == 1 {
					return initial
				}
				return expiry
			})
			out, e := s.OverviewView(ctx, snap.Approval.DeviceID, initial)
			if !errors.Is(e, overviewledger.ErrExpired) || !reflect.DeepEqual(out, OverviewStatus{}) {
				t.Fatal("stale available/pending label escaped after COMMIT", e)
			}
			out, e = s.OverviewView(WithOverviewClock(context.Background(), func() time.Time { return expiry }), snap.Approval.DeviceID, expiry)
			if e != nil || out.Processes.Transfer == nil || out.Processes.Transfer.State != "expired" {
				t.Fatal("expired metadata was erased instead of marked expired", e)
			}
			if state == "complete" && (out.Processes.Complete == nil || !out.Processes.Complete.Manifest.CaptureStartedAt.Equal(capture)) {
				t.Fatal("expired capture age changed")
			}
		})
	}
}
