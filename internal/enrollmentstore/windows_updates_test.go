package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsupdates"
	"localrmm/internal/windowsvolumes"
	"strings"
	"testing"
	"time"
)

func windowsUpdatesStoreFrame(t *testing.T, sequence uint64, at time.Time) []byte {
	t.Helper()
	var frame lanstore.Frame
	if err := json.Unmarshal(windowsStoreFrame(t, sequence, at), &frame); err != nil {
		t.Fatal(err)
	}
	frame.SchemaVersion = lanstore.FrameWindowsUpdatesVersion
	frame.WindowsUpdates = &windowsupdates.Snapshot{SchemaVersion: windowsupdates.SchemaVersion, Scope: windowsupdates.Scope, GrantID: strings.Repeat("9", 32), GenerationID: frame.WindowsInventory.GenerationID, CollectedAt: at, Source: "wua-cache", CacheFreshness: "unknown", Quality: "observed", CountExact: true, ObservedCount: 1, Rows: []windowsupdates.Update{{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 1, Title: "Private invented cached update", KBArticleIDs: []string{"KB123456"}, Severity: "important"}}}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWindowsUpdatesDurablePrivateReplayAndCaptureFloor(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			f, s, path, identity, cert := activeWindowsStore(t, transport)
			ctx := context.Background()
			at := time.Unix(testNow+10, 0).UTC()
			raw := windowsUpdatesStoreFrame(t, 1, at)
			first, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, at)
			if err != nil {
				t.Fatal(err)
			}
			view, err := s.WindowsInventoryView(ctx, identity.Approval.DeviceID, at)
			if err != nil || view.Updates == nil || view.Updates.Source != "wua-cache" || view.Updates.CacheFreshness != "unknown" || !view.Updates.CollectedAt.Equal(at) || view.ReceivedAt == nil || !view.ReceivedAt.Equal(at) {
				t.Fatal("private update projection failed", err)
			}
			basic, err := s.LatestObservations(ctx)
			if err != nil {
				t.Fatal(err)
			}
			basicRaw, _ := json.Marshal(basic)
			for _, private := range []string{"Private invented cached update", "KB123456", "windowsUpdates", "wua-cache"} {
				if bytes.Contains(basicRaw, []byte(private)) {
					t.Fatal("private update escaped into health/provider evidence")
				}
			}
			s.Close()
			s = f.open(t, path)
			retry, err := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), raw, at.Add(3*time.Minute))
			if err != nil || !retry.Duplicate || !retry.ReceivedAt.Equal(first.ReceivedAt) || !retry.CollectedAt.Equal(first.CollectedAt) {
				t.Fatal("lost-response exact retry renewed original age", err)
			}
			view, err = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, at.Add(3*time.Minute))
			if err != nil || view.Status != "stale" || view.Updates == nil || !view.Updates.CollectedAt.Equal(at) || !view.ReceivedAt.Equal(at) {
				t.Fatal("stale update hidden or capture refreshed", err)
			}
			// An absent scope advances the durable base floor without refreshing
			// the old update or retaining its private rows in a later generation.
			nextAt := at.Add(30 * time.Second)
			if _, err = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), windowsStoreFrame(t, 2, nextAt), nextAt); err != nil {
				t.Fatal(err)
			}
			view, err = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, nextAt)
			if err != nil || view.Updates != nil || view.Sequence == nil || *view.Sequence != 2 {
				t.Fatal("scope-absent frame retained update data", err)
			}
			var rollback lanstore.Frame
			json.Unmarshal(windowsUpdatesStoreFrame(t, 3, at.Add(time.Minute)), &rollback)
			rollback.WindowsInventory.CollectedAt = at
			rollback.WindowsUpdates.CollectedAt = at
			bad, _ := json.Marshal(rollback)
			if _, err = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), bad, at.Add(time.Minute)); !errors.Is(err, lanstore.ErrReplay) {
				t.Fatal("absent frame erased update/base capture floor", err)
			}
			// A malformed frame must not consume the next usable sequence.
			nextRaw := windowsUpdatesStoreFrame(t, 3, at.Add(time.Minute))
			bad = bytes.Replace(nextRaw, []byte(`"observedCount":1,"truncated":false,"rows":[{"updateId"`), []byte(`"observedCount":0,"truncated":false,"rows":[{"updateId"`), 1)
			if bytes.Equal(bad, nextRaw) {
				t.Fatal("tamper fixture did not target update count")
			}
			if _, err = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), bad, at.Add(time.Minute)); !errors.Is(err, lanstore.ErrFrame) {
				t.Fatal("tampered update accepted", err)
			}
			if _, err = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), nextRaw, at.Add(time.Minute)); err != nil {
				t.Fatal("rejected frame consumed sequence", err)
			}
			ctl := control(identity, 20)
			ctl.Now = at.Add(2 * time.Minute).Unix()
			if _, err = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: ctl, State: enrollmentstate.Revoked}); err != nil {
				t.Fatal(err)
			}
			view, err = s.WindowsInventoryView(ctx, identity.Approval.DeviceID, at.Add(2*time.Minute))
			if err != nil || view.Status != "revoked" || view.Updates != nil || view.Snapshot != nil {
				t.Fatal("revoked identity leaked updates", err)
			}
			if _, err = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), nextRaw, at.Add(2*time.Minute)); err == nil {
				t.Fatal("revoked identity replay was acknowledged")
			}
		})
	}
}

func TestWindowsUpdatesPrivateIndependentExpiryAndReceipt(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	young := now.Add(-time.Minute)
	old := now.Add(-24 * time.Hour)
	seq := uint64(1)
	base := WindowsInventoryView{ServerNow: now, Status: "fresh", Sequence: &seq, ReceivedAt: &young, Snapshot: &windowsmanaged.Snapshot{CollectedAt: young}, Updates: &windowsupdates.Snapshot{CollectedAt: old}, Volumes: &windowsvolumes.Snapshot{CollectedAt: young}}
	view, err := base.RecheckAt(now)
	if err != nil || view.Updates != nil || view.Volumes == nil || !view.ReceivedAt.Equal(young) {
		t.Fatal("update privacy expiry changed sibling or receipt", err)
	}
	base.Updates = &windowsupdates.Snapshot{CollectedAt: young}
	base.Volumes = &windowsvolumes.Snapshot{CollectedAt: old}
	view, err = base.RecheckAt(now)
	if err != nil || view.Updates == nil || view.Volumes != nil {
		t.Fatal("independent volume expiry removed updates", err)
	}
	for _, kind := range []string{"revoked", "certificate", "base-expired", "base-missing"} {
		t.Run(kind, func(t *testing.T) {
			v := base
			switch kind {
			case "revoked":
				v.Status = "revoked"
			case "certificate":
				v.certificateNotAfter = now.Unix()
			case "base-expired":
				v.Snapshot = &windowsmanaged.Snapshot{CollectedAt: old}
			case "base-missing":
				v.Snapshot = nil
			}
			v, err := v.RecheckAt(now)
			if err != nil || v.Updates != nil {
				t.Fatal("private update outlived authority/base", err)
			}
		})
	}
	base.Updates = &windowsupdates.Snapshot{CollectedAt: young}
	base.certificateNotAfter = now.Add(time.Second).Unix()
	view, err = base.RecheckAt(now.Add(time.Second))
	if err != nil || view.Status != "revoked" || view.Updates != nil {
		t.Fatal("slow response outlived certificate", err)
	}
	if _, err = base.RecheckAt(now.Add(-time.Nanosecond)); err == nil {
		t.Fatal("clock rollback accepted")
	}
}

func TestWindowsUpdatesCannotBeAdmittedUnderBasicIdentity(t *testing.T) {
	_, s, _, identity, cert := activeFixture(t)
	at := time.Unix(testNow+10, 0).UTC()
	if _, err := s.SaveObservation(context.Background(), identity.InvitationID, cert.CertificateHash(), windowsUpdatesStoreFrame(t, 1, at), at); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("basic identity gained update scope", err)
	}
}
