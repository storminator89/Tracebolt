package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/windowsnetworkcontext"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func reviewerLongNetworkContextFixture(t *testing.T) networkContextFixture {
	f, s, path, snap, cert := reviewerLongWindowsStore(t, "tls")
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsNetworkContext(context.Background()); e != nil {
		t.Fatal(e)
	}
	c := windowsnetworkcontext.Consent{SchemaVersion: windowsnetworkcontext.ConsentVersion, Scope: windowsnetworkcontext.Scope, SenderBinding: windowsnetworkcontext.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at}
	return networkContextFixture{f, s, path, snap, cert, at, c}
}
func TestReviewerNetworkContextOriginalExpiryAcrossFinalConnectionWait(t *testing.T) {
	for _, kind := range []string{"source-receipt", "source-page", "cursor-page"} {
		t.Run(kind, func(t *testing.T) {
			f := reviewerLongNetworkContextFixture(t)
			defer f.s.Close()
			f.grant(t)
			msgs := f.messages(t, 1, 129, f.at)
			for _, m := range msgs {
				if _, e := f.apply(t, m, f.at); e != nil {
					t.Fatal(e)
				}
			}
			sourceExpiry := msgs[0].Manifest.ExpiresAt
			beforeAt := sourceExpiry.Add(-time.Second)
			if kind == "cursor-page" {
				beforeAt = f.at.Add(time.Second)
			}
			page := f.page(t, networkContextQuery(), beforeAt)
			if page.Complete == nil || page.NextCursor == "" || page.CursorExpiresAt == nil {
				t.Fatal("missing complete cursor fixture")
			}
			expires := sourceExpiry
			if kind == "cursor-page" {
				expires = *page.CursorExpiresAt
			}
			if !expires.Before(time.Unix(f.snap.Intent.NotAfter, 0)) {
				t.Fatal("fixture identity expires before original page/source deadline")
			}
			held, e := f.s.db.Conn(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer held.Close()
			waits := f.s.db.Stats().WaitCount
			var now atomic.Int64
			now.Store(beforeAt.Unix())
			ctx := WithWindowsNetworkContextClock(WithWindowsNetworkContextIngressOrigin(context.Background(), f.snap.Binding.Origin), func() time.Time { return time.Unix(now.Load(), 0).UTC() })
			type result struct {
				at  time.Time
				err error
			}
			done := make(chan result, 1)
			go func() {
				if kind == "source-receipt" {
					at, e := f.s.RecheckWindowsNetworkContext(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, beforeAt)
					done <- result{at, e}
				} else {
					done <- result{err: f.s.RecheckWindowsNetworkContextPage(ctx, page, beforeAt)}
				}
			}()
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			poll := time.NewTicker(time.Millisecond)
			defer poll.Stop()
			for f.s.db.Stats().WaitCount == waits {
				select {
				case <-poll.C:
				case <-timer.C:
					t.Fatal("final check never blocked on connection")
				}
			}
			now.Store(expires.Unix())
			if e := held.Close(); e != nil {
				t.Fatal(e)
			}
			select {
			case got := <-done:
				if kind == "source-receipt" {
					if got.err != nil {
						t.Fatal("still-valid identity rejected", got.err)
					}
					if got.at.Before(expires) {
						t.Fatal("returned receipt clock would let original source expiry escape after connection wait")
					}
				} else if got.err == nil {
					t.Fatal("expired original page/source cursor survived final connection wait")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("final check stalled")
			}
		})
	}
}

func TestNetworkContextOriginalStagingExpiryAcrossFinalReceiptWait(t *testing.T) {
	f := newNetworkContextFixture(t, "tls")
	defer f.s.Close()
	f.grant(t)
	m := f.messages(t, 1, 129, f.at)[0]
	if _, e := f.apply(t, m, f.at); e != nil {
		t.Fatal(e)
	}
	expiry := f.at.Add(15 * time.Minute)
	before := expiry.Add(-time.Second)
	held, e := f.s.db.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer held.Close()
	waits := f.s.db.Stats().WaitCount
	var now atomic.Int64
	now.Store(before.Unix())
	ctx := WithWindowsNetworkContextClock(WithWindowsNetworkContextIngressOrigin(context.Background(), f.snap.Binding.Origin), func() time.Time { return time.Unix(now.Load(), 0).UTC() })
	done := make(chan error, 1)
	go func() {
		_, e := f.s.RecheckWindowsNetworkContextMessage(ctx, f.snap.InvitationID, f.cert.CertificateHash(), m, before)
		done <- e
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for f.s.db.Stats().WaitCount == waits {
		select {
		case <-tick.C:
		case <-timer.C:
			t.Fatal("receipt did not wait")
		}
	}
	now.Store(expiry.Unix())
	if e = held.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		if !errors.Is(e, windowsnetworkcontext.ErrExpired) {
			t.Fatal("original staging deadline escaped", e)
		}
	case <-timer.C:
		t.Fatal("final receipt wait stalled")
	}
}
