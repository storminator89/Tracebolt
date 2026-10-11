package enrollmentstore

import (
	"context"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/windowsfullservices"
	"localrmm/internal/windowsmanaged"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func reviewerLongWindowsStore(t *testing.T, profile string) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f := newFixture(t)
	f.config.Binding.CollectionProfile = windowsmanaged.CollectionProfile
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	f.challenge.CollectionProfile = windowsmanaged.CollectionProfile
	if profile == "http-test" {
		f.config.Binding.Profile = profile
		f.config.Binding.Origin = "http://manager.example"
		f.challenge.Profile = profile
		f.challenge.Origin = f.config.Binding.Origin
	}
	path := filepath.Join(t.TempDir(), "private", "windows.sqlite")
	s := f.open(t, path)
	ctx := context.Background()
	create := f.createCommand()
	create.Platform = "windows"
	v, e := s.CreateInvitation(ctx, create)
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(v, 2), ClaimID: f.challenge.ClaimID}, f.claim(t))
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(v, 3), DeviceID: id("agent", 1), KeyFingerprint: v.Claim.KeyFingerprint})
	if e != nil {
		t.Fatal(e)
	}
	v, e = s.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: f.control(v, 4), IntentID: id("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentstate.TemplateVersion, NotBefore: testNow, NotAfter: testNow + 3*86400})
	if e != nil {
		t.Fatal(e)
	}
	intent, e := s.SigningIntent(ctx, v.InvitationID, v.UpdatedAt)
	if e != nil {
		t.Fatal(e)
	}
	cert := f.issue(t, intent)
	v, e = s.CommitIssued(ctx, f.control(v, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	control := f.control(v, 6)
	v, e = s.Activate(ctx, control, f.activation(t, cert, control))
	if e != nil {
		t.Fatal(e)
	}
	return f, s, path, v, cert
}
func reviewerLongFullServicesFixture(t *testing.T) fullServicesFixture {
	f, s, path, snap, cert := reviewerLongWindowsStore(t, "tls")
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.InitializeWindowsFullServices(context.Background()); e != nil {
		t.Fatal(e)
	}
	c := windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: windowsfullservices.SenderBinding(snap.Binding.Profile, snap.Binding.Origin, cert.CertificateHash(), snap.Approval.DeviceID), GrantID: strings.Repeat("b", 32), Revision: 1, Enabled: true, ChangedAt: at}
	return fullServicesFixture{f, s, path, snap, cert, at, c}
}
func TestReviewerFullServicesOriginalExpiryAcrossFinalConnectionWait(t *testing.T) {
	for _, kind := range []string{"source-receipt", "source-page", "cursor-page"} {
		t.Run(kind, func(t *testing.T) {
			f := reviewerLongFullServicesFixture(t)
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
			page := f.page(t, fullQuery(), beforeAt)
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
			ctx := WithWindowsFullServicesClock(WithWindowsFullServicesIngressOrigin(context.Background(), f.snap.Binding.Origin), func() time.Time { return time.Unix(now.Load(), 0).UTC() })
			type result struct {
				at  time.Time
				err error
			}
			done := make(chan result, 1)
			go func() {
				if kind == "source-receipt" {
					at, e := f.s.RecheckWindowsFullServices(ctx, f.snap.InvitationID, f.cert.CertificateHash(), f.consent, beforeAt)
					done <- result{at, e}
				} else {
					done <- result{err: f.s.RecheckWindowsFullServicesPage(ctx, page, beforeAt)}
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
