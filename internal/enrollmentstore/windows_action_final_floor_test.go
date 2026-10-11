package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsaction"
	"localrmm/internal/windowsactionjob"
	"strings"
	"testing"
	"time"
)

func TestReviewWindowsActionFinalClaimExpiryMustPersistClock(t *testing.T) {
	s, key, b, at, id, hash := windowsActionFixture(t)
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	ctx := context.Background()
	actor := "operator_" + strings.Repeat("2", 32)
	caps := windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: at.Unix(), Enabled: true}
	if e := s.ReportWindowsServiceActions(ctx, pub, id, hash, caps, at); e != nil {
		t.Fatal(e)
	}
	r, e := s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat("3", 32), actor, b.Target, windowsaction.Restart, at)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, r.Preview.ID, r.Preview.Digest, actor, at, signWindowsAction(key))
	if e != nil {
		t.Fatal(e)
	}
	identity := r.Jobs[0].Identity()
	calls := 0
	before := at.Add(59 * time.Second)
	crossed := at.Add(61 * time.Second)
	c := WithOverviewClock(ctx, func() time.Time {
		calls++
		if calls == 1 {
			return before
		}
		return crossed
	})
	if g, e := s.ClaimWindowsServiceAction(c, pub, id, hash, identity, before); !errors.Is(e, windowsaction.ErrExpired) || len(g.Envelope) != 0 {
		t.Fatalf("first claim did not fail expired: %v envelope=%d", e, len(g.Envelope))
	}
	var savedRaw []byte
	if e := s.db.QueryRow(`SELECT body FROM enrollment_windows_action_records WHERE invitation_id=?`, id).Scan(&savedRaw); e != nil {
		t.Fatal(e)
	}
	var saved windowsactionjob.Record
	if e := windowsaction.DecodeCanonical(savedRaw, &saved, windowsactionjob.MaxRecordBytes); e != nil {
		t.Fatal(e)
	}
	oldJobs, _ := json.Marshal(r.Jobs)
	newJobs, _ := json.Marshal(saved.Jobs)
	oldCaps, _ := json.Marshal(r.Capabilities)
	newCaps, _ := json.Marshal(saved.Capabilities)
	if saved.RejectedClockFloor == nil || !saved.RejectedClockFloor.Equal(crossed) || !saved.ClockFloor.Equal(r.ClockFloor) || !bytes.Equal(oldJobs, newJobs) || !bytes.Equal(oldCaps, newCaps) {
		t.Fatal("rejection changed work or lost final observation")
	}
	if e := s.OpenWindowsServiceActions(ctx, pub); e != nil {
		t.Fatal("rejected floor unreadable", e)
	}
	if calls < 2 {
		t.Fatalf("final guard not reached: %d", calls)
	}
	g, e := s.ClaimWindowsServiceAction(ctx, pub, id, hash, identity, before)
	if e == nil || len(g.Envelope) != 0 {
		t.Fatalf("observed final expiry revived after rollback: err=%v envelope=%d clockCalls=%d", e, len(g.Envelope), calls)
	}
}

func TestWindowsActionFinalObservationPreservesAuthorityAndSuccessfulClock(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "authority-expiry"}[expire], func(t *testing.T) {
			s, key, b, at, id, hash := windowsActionFixture(t)
			pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
			ctx := context.Background()
			actor := "operator_" + strings.Repeat("2", 32)
			if e := s.ReportWindowsServiceActions(ctx, pub, id, hash, windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: at.Unix(), Enabled: true}, at); e != nil {
				t.Fatal(e)
			}
			r, e := s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat("3", 32), actor, b.Target, windowsaction.Restart, at)
			if e != nil {
				t.Fatal(e)
			}
			r, e = s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, r.Preview.ID, r.Preview.Digest, actor, at, signWindowsAction(key))
			if e != nil {
				t.Fatal(e)
			}
			initial, final := at.Add(time.Second), at.Add(2*time.Second)
			if expire {
				if e = s.transact(ctx, func(tr *transaction) error {
					snap, e := tr.engine.Get(id)
					final = time.Unix(snap.Intent.NotAfter+1, 0).UTC()
					return e
				}); e != nil {
					t.Fatal(e)
				}
			}
			calls := 0
			c := WithOverviewClock(ctx, func() time.Time {
				calls++
				if calls == 1 {
					return initial
				}
				return final
			})
			g, e := s.ClaimWindowsServiceAction(c, pub, id, hash, r.Jobs[0].Identity(), initial)
			if expire && (e == nil || len(g.Envelope) != 0) || !expire && (e != nil || !bytes.Equal(g.Envelope, r.Jobs[0].Envelope)) {
				t.Fatal("claim result", e)
			}
			var raw []byte
			if e = s.db.QueryRow(`SELECT body FROM enrollment_windows_action_records WHERE invitation_id=?`, id).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			var saved windowsactionjob.Record
			if windowsaction.DecodeCanonical(raw, &saved, windowsactionjob.MaxRecordBytes) != nil || !saved.EffectiveClockFloor().Equal(final) {
				t.Fatal("final floor not durable")
			}
			if expire {
				if saved.RejectedClockFloor == nil || saved.Jobs[0].ClaimedAt != nil || !saved.ClockFloor.Equal(r.ClockFloor) {
					t.Fatal("expired authority consumed work")
				}
			} else if saved.RejectedClockFloor != nil || saved.Jobs[0].ClaimedAt == nil || !saved.Jobs[0].ClaimedAt.Equal(initial) {
				t.Fatal("successful original claim timestamp changed")
			}
			if e = s.OpenWindowsServiceActions(ctx, pub); e != nil {
				t.Fatal("durable state invalid", e)
			}
			if _, _, e = s.WindowsServiceActionView(ctx, pub, b.EndpointID, initial); e == nil {
				t.Fatal("final observation rolled back")
			}
		})
	}
}
