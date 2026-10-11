package enrollmentstore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestProcessesReviewerFinalRecheckCannotUseClockBeforeConnectionWait(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	held, e := f.s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	var now atomic.Int64
	now.Store(f.at.Add(time.Second).Unix())
	sampled := make(chan struct{}, 1)
	ctx := WithWindowsFullProcessesClock(WithWindowsFullProcessesIngressOrigin(context.Background(), f.snap.Binding.Origin), func() time.Time {
		value := time.Unix(now.Load(), 0).UTC()
		select {
		case sampled <- struct{}{}:
		default:
		}
		return value
	})
	done := make(chan error, 1)
	go func() {
		_, e := f.s.RecheckWindowsFullProcesses(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at)
		done <- e
	}()
	select {
	case <-sampled:
	case <-time.After(5 * time.Second):
		t.Fatal("final check did not reach pre-connection clock")
	}
	now.Store(f.snap.Intent.NotAfter)
	if e := held.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("final receipt authorized with stale pre-connection time after certificate expiry")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("final check stalled")
	}
}

func TestProcessesReviewerFinalPageGuardCannotUseClockBeforeConnectionWait(t *testing.T) {
	f := newFullProcessesFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	page := f.page(t, processesQuery(), f.at)
	held, e := f.s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	before := f.s.db.Stats().WaitCount
	var now atomic.Int64
	now.Store(f.at.Add(time.Second).Unix())
	ctx := WithWindowsFullProcessesClock(context.Background(), func() time.Time { return time.Unix(now.Load(), 0).UTC() })
	done := make(chan error, 1)
	go func() { done <- f.s.RecheckWindowsFullProcessesPage(ctx, page, f.at.Add(time.Second)) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for f.s.db.Stats().WaitCount == before {
		select {
		case <-poll.C:
		case <-deadline.C:
			t.Fatal("page guard never waited for connection")
		}
	}
	now.Store(f.snap.Intent.NotAfter)
	if e := held.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("page guard authorized using stale pre-connection time after certificate expiry")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("page guard stalled")
	}
}

// A final authority observation may not refresh the accepted action or its
// replay/reservation metadata, including when a blocked guard is canceled.
func TestWindowsFullProcessesFinalGuardReadOnlyAndCanceledWait(t *testing.T) {
	for _, kind := range []string{"receipt", "page"} {
		t.Run(kind, func(t *testing.T) {
			f := newFullProcessesFixture(t, "tls")
			defer f.s.Close()
			f.grant(t)
			for _, m := range f.messages(t, 1, 129, f.at) {
				if _, e := f.apply(t, m, f.at); e != nil {
					t.Fatal(e)
				}
			}
			page := f.page(t, processesQuery(), f.at)
			type saved struct {
				Authority, Clock                                                  string
				Generations, Rows, Chunks, Reserved, Stored, NextRows, NextChunks int64
			}
			snapshot := func() saved {
				var v saved
				if e := f.s.db.QueryRow(`SELECT CAST(body AS TEXT) FROM wfp_authority WHERE device=?`, f.snap.Approval.DeviceID).Scan(&v.Authority); e != nil {
					t.Fatal(e)
				}
				if e := f.s.db.QueryRow(`SELECT last_time FROM wfp_meta WHERE id=1`).Scan(&v.Clock); e != nil {
					t.Fatal(e)
				}
				if e := f.s.db.QueryRow(`SELECT count(*),coalesce(sum(reserved_bytes),0),coalesce(sum(stored_bytes),0),coalesce(sum(next_row),0),coalesce(sum(next_chunk),0) FROM wfp_generations`).Scan(&v.Generations, &v.Reserved, &v.Stored, &v.NextRows, &v.NextChunks); e != nil {
					t.Fatal(e)
				}
				if e := f.s.db.QueryRow(`SELECT (SELECT count(*) FROM wfp_rows),(SELECT count(*) FROM wfp_chunks)`).Scan(&v.Rows, &v.Chunks); e != nil {
					t.Fatal(e)
				}
				return v
			}
			before := snapshot()
			at := f.at.Add(time.Second)
			base := WithWindowsFullProcessesClock(WithWindowsFullProcessesIngressOrigin(context.Background(), f.snap.Binding.Origin), func() time.Time { return at })
			check := func(ctx context.Context) error {
				if kind == "receipt" {
					checked, e := f.s.RecheckWindowsFullProcesses(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, f.at)
					if e == nil && !checked.Equal(at) {
						t.Error("final checked time was not fresh")
					}
					return e
				}
				return f.s.RecheckWindowsFullProcessesPage(ctx, page, f.at)
			}
			if e := check(base); e != nil {
				t.Fatal(e)
			}
			if after := snapshot(); after != before {
				t.Fatal("successful final guard mutated original metadata")
			}
			held, e := f.s.db.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer held.Close()
			waits := f.s.db.Stats().WaitCount
			ctx, cancel := context.WithCancel(base)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- check(ctx) }()
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			poll := time.NewTicker(time.Millisecond)
			defer poll.Stop()
			for f.s.db.Stats().WaitCount == waits {
				select {
				case <-poll.C:
				case <-deadline.C:
					t.Fatal("guard did not wait for connection")
				}
			}
			cancel()
			select {
			case e := <-done:
				if !errors.Is(e, context.Canceled) {
					t.Fatal("waiting guard lost cancellation", e)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("canceled guard stalled")
			}
			if e = held.Close(); e != nil {
				t.Fatal(e)
			}
			if after := snapshot(); after != before {
				t.Fatal("canceled guard mutated original metadata")
			}
		})
	}
}
