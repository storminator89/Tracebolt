package enrollmentstore

import (
	"context"
	"crypto/ed25519"
	"localrmm/internal/windowsaction"
	"strings"
	"testing"
	"time"
)

// Every history route uses this exact View seam. Saved approvals are never an
// alternative source of authority after a live credential's final expiry.
func TestWindowsActionHistoryViewPreservesFinalAuthority(t *testing.T) {
	s, key, b, at, id, hash := windowsActionFixture(t)
	ctx := context.Background()
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	if e := s.ReportWindowsServiceActions(ctx, pub, id, hash, windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: at.Unix(), Enabled: true}, at); e != nil {
		t.Fatal(e)
	}
	r, e := s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat("3", 32), "operator_"+strings.Repeat("2", 32), b.Target, "start", at)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, r.Preview.ID, r.Preview.Digest, r.Preview.ActorID, at, signWindowsAction(key))
	if e != nil {
		t.Fatal(e)
	}
	original := r.Jobs[0]
	var expired time.Time
	if e = s.transact(ctx, func(tr *transaction) error {
		snap, e := tr.engine.Get(id)
		expired = time.Unix(tr.currentCredentialNotAfter(snap), 0).UTC()
		return e
	}); e != nil {
		t.Fatal(e)
	}
	calls := 0
	clock := WithOverviewClock(ctx, func() time.Time {
		calls++
		if calls == 1 {
			return at.Add(time.Second)
		}
		return expired
	})
	if _, _, e = s.WindowsServiceActionView(clock, pub, b.EndpointID, at.Add(time.Second)); e == nil || calls < 2 {
		t.Fatal("history passed final credential expiry", e, calls)
	}
	if _, _, e = s.WindowsServiceActionView(ctx, pub, b.EndpointID, at.Add(time.Second)); e == nil {
		t.Fatal("history revived after clock rollback")
	}
	var raw []byte
	if e = s.db.QueryRow(`SELECT body FROM enrollment_windows_action_records WHERE invitation_id=?`, id).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), original.Preview.ID) || !strings.Contains(string(raw), `"claimedAt":null`) {
		t.Fatal("reading history consumed or lost approval")
	}
}
