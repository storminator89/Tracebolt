package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsaction"
	"os"
	"strings"
	"testing"
	"time"
)

func windowsActionFixture(t *testing.T) (*Store, []byte, windowsaction.Binding, time.Time, string, string) {
	t.Helper()
	_, s, _, snap, cert := activeWindowsStore(t, "tls")
	t.Cleanup(func() { s.Close() })
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	pub := key.Public().(ed25519.PublicKey)
	at := time.Unix(testNow+10, 0).UTC()
	b := windowsaction.Binding{ManagerID: snap.Binding.InstanceID, KeyID: windowsaction.Digest(pub), EndpointID: snap.Approval.DeviceID, IncarnationDigest: "sha256:" + cert.CertificateHash(), InstallationID: "broker_" + strings.Repeat("1", 32), GrantDigest: windowsaction.Digest([]byte("fixture grant")), Target: "FixtureService", TargetDigest: windowsaction.Digest([]byte("fixture config"))}
	var before []byte
	if e := s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, snap.InvitationID).Scan(&before); e != nil {
		t.Fatal(e)
	}
	var legacy credential
	if json.Unmarshal(before, &legacy) != nil {
		t.Fatal("credential")
	}
	round, _ := json.Marshal(legacy)
	if !bytes.Equal(round, before) || legacy.WindowsActionSetup != nil {
		t.Fatal("old optional bytes changed")
	}
	if e := s.OpenWindowsServiceActions(context.Background(), pub); !errors.Is(e, windowsaction.ErrUnavailable) {
		t.Fatal("startup initialized missing state", e)
	}
	if e := s.SetupWindowsServiceActionsCreateOnly(context.Background(), pub, b, at); e != nil {
		t.Fatal("setup", e)
	}
	if e := s.SetupWindowsServiceActionsCreateOnly(context.Background(), pub, b, at); e == nil {
		t.Fatal("setup adopted used domain")
	}
	return s, key, b, at, snap.InvitationID, cert.CertificateHash()
}
func signWindowsAction(key []byte) func(windowsaction.Permit) ([]byte, error) {
	return func(p windowsaction.Permit) ([]byte, error) {
		b, e := windowsaction.SigningMessage(p)
		if e != nil {
			return nil, e
		}
		return windowsaction.Encode(p, ed25519.Sign(ed25519.PrivateKey(key), b))
	}
}
func TestWindowsServiceActionThreeOperationsClaimOnceAndResults(t *testing.T) {
	s, key, b, at, id, hash := windowsActionFixture(t)
	ctx := context.Background()
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	actor := "operator_" + strings.Repeat("2", 32)
	for n, op := range []string{windowsaction.Start, windowsaction.Stop, windowsaction.Restart} {
		now := at.Add(time.Duration(n) * time.Second)
		c := windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: now.Unix(), Enabled: true}
		if e := s.ReportWindowsServiceActions(ctx, pub, id, hash, c, now); e != nil {
			t.Fatal(e)
		}
		r, e := s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat(string(rune('3'+n)), 32), actor, b.Target, op, now)
		if e != nil {
			t.Fatal("preview", op, e)
		}
		p := r.Preview
		r, e = s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, p.ID, p.Digest, actor, now, signWindowsAction(key))
		if e != nil {
			t.Fatal("approve", e)
		}
		j := r.Jobs[len(r.Jobs)-1]
		retried, e := s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, p.ID, p.Digest, actor, now.Add(time.Millisecond), func(windowsaction.Permit) ([]byte, error) { t.Fatal("approval signed twice"); return nil, nil })
		if e != nil || !bytes.Equal(retried.Jobs[n].Envelope, j.Envelope) {
			t.Fatal("approval changed bytes", e)
		}
		g, e := s.ClaimWindowsServiceAction(ctx, pub, id, hash, j.Identity(), now.Add(time.Millisecond))
		if e != nil || !bytes.Equal(g.Envelope, j.Envelope) {
			t.Fatal("claim", e)
		}
		if again, e := s.ClaimWindowsServiceAction(ctx, pub, id, hash, j.Identity(), now.Add(time.Millisecond)); !errors.Is(e, windowsaction.ErrConsumed) || len(again.Envelope) != 0 {
			t.Fatal("claim repeated", e)
		}
		result := windowsaction.Result{Version: windowsaction.ResultVersion, Identity: j.Identity(), Operation: op, Target: b.Target, Deadline: j.Deadline().Unix(), Phase: "complete", Outcome: "running-observed", Observations: 2, LastObservedState: 4}
		if op != windowsaction.Start {
			result.StopAttempted = true
			result.StopRequested = true
			result.StoppedObserved = true
		}
		if op != windowsaction.Stop {
			result.StartAttempted = true
			result.StartRequested = true
			result.RunningObserved = true
		} else {
			result.Outcome = "stopped-observed"
			result.LastObservedState = 1
		}
		if e = s.AcceptWindowsServiceAction(ctx, pub, id, hash, result, now.Add(time.Millisecond)); e != nil {
			t.Fatal("result", e)
		}
		if e = s.AcceptWindowsServiceAction(ctx, pub, id, hash, result, now.Add(time.Millisecond)); e != nil {
			t.Fatal("exact result retry", e)
		}
		result.Outcome = "intervention-required"
		if e = s.AcceptWindowsServiceAction(ctx, pub, id, hash, result, now.Add(time.Millisecond)); e == nil {
			t.Fatal("changed terminal result accepted")
		}
	}
}
func TestWindowsServiceActionMissingUsedRowsHardStop(t *testing.T) {
	for _, drop := range []string{`DELETE FROM enrollment_windows_action_records`, `DROP TABLE enrollment_windows_action_records; DROP TABLE enrollment_windows_action_meta`} {
		t.Run(drop, func(t *testing.T) {
			s, key, _, _, _, _ := windowsActionFixture(t)
			if _, e := s.db.Exec(drop); e != nil {
				t.Fatal(e)
			}
			if e := s.OpenWindowsServiceActions(context.Background(), ed25519.PrivateKey(key).Public().(ed25519.PublicKey)); !errors.Is(e, ErrStorage) {
				t.Fatal("used state recreated", e)
			}
		})
	}
}
func TestWindowsServiceActionStaleCapabilityExpiryAndClockFloor(t *testing.T) {
	s, key, b, at, id, hash := windowsActionFixture(t)
	ctx := context.Background()
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	actor := "operator_" + strings.Repeat("2", 32)
	cap := windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: at.Unix(), Enabled: true}
	if e := s.ReportWindowsServiceActions(ctx, pub, id, hash, cap, at); e != nil {
		t.Fatal(e)
	}
	if _, e := s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat("3", 32), actor, b.Target, "restart", at.Add(time.Minute)); !errors.Is(e, windowsaction.ErrUnavailable) {
		t.Fatal("stale preview", e)
	}
	if _, _, e := s.WindowsServiceActionView(ctx, pub, b.EndpointID, at); !errors.Is(e, ErrStorage) {
		t.Fatal("rollback revived stale capability", e)
	}
	s, key, b, at, id, hash = windowsActionFixture(t)
	pub = ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	cap.Binding = b
	cap.CapturedAt = at.Unix()
	if e := s.ReportWindowsServiceActions(ctx, pub, id, hash, cap, at); e != nil {
		t.Fatal(e)
	}
	r, e := s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat("3", 32), actor, b.Target, "restart", at)
	if e != nil {
		t.Fatal(e)
	}
	p := r.Preview
	if _, e = s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, p.ID, p.Digest, actor, at.Add(time.Minute), signWindowsAction(key)); !errors.Is(e, windowsaction.ErrExpired) {
		t.Fatal("expired preview", e)
	}
	if _, _, e = s.WindowsServiceActionView(ctx, pub, b.EndpointID, at); !errors.Is(e, ErrStorage) {
		t.Fatal("rollback revived expiry", e)
	}
}
func TestWindowsServiceActionSignerSubstitutionAtomicAndIntervention(t *testing.T) {
	s, key, b, at, id, hash := windowsActionFixture(t)
	ctx := context.Background()
	pub := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
	actor := "operator_" + strings.Repeat("2", 32)
	if e := s.ReportWindowsServiceActions(ctx, pub, id, hash, windowsaction.Capabilities{Version: windowsaction.CapabilitiesVersion, Binding: b, CapturedAt: at.Unix(), Enabled: true}, at); e != nil {
		t.Fatal(e)
	}
	r, e := s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat("3", 32), actor, b.Target, "start", at)
	if e != nil {
		t.Fatal(e)
	}
	p := r.Preview
	_, e = s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, p.ID, p.Digest, actor, at, func(p windowsaction.Permit) ([]byte, error) { p.Operation = "stop"; return signWindowsAction(key)(p) })
	if !errors.Is(e, windowsaction.ErrBinding) {
		t.Fatal("signed substitution", e)
	}
	r, _, e = s.WindowsServiceActionView(ctx, pub, b.EndpointID, at)
	if e != nil || len(r.Jobs) != 0 || r.Sequence != 0 {
		t.Fatal("failed signing consumed state", e)
	}
	r, e = s.ApproveWindowsServiceAction(ctx, pub, b.EndpointID, p.ID, p.Digest, actor, at, signWindowsAction(key))
	if e != nil {
		t.Fatal(e)
	}
	j := r.Jobs[0]
	if _, e = s.ClaimWindowsServiceAction(ctx, pub, id, hash, j.Identity(), at); e != nil {
		t.Fatal(e)
	}
	result := windowsaction.Result{Version: windowsaction.ResultVersion, Identity: j.Identity(), Operation: "start", Target: b.Target, Deadline: j.Deadline().Unix(), Phase: "complete", Outcome: "intervention-required", StartAttempted: true}
	if e = s.AcceptWindowsServiceAction(ctx, pub, id, hash, result, at); e != nil {
		t.Fatal(e)
	}
	r, _, e = s.WindowsServiceActionView(ctx, pub, b.EndpointID, at)
	if e != nil || r.Ready(at) != "job_pending" || r.Jobs[0].State(at) != "needs_intervention" {
		t.Fatal("uncertain action unblocked", e)
	}
	if _, e = s.PreviewWindowsServiceAction(ctx, pub, b.EndpointID, "action_"+strings.Repeat("4", 32), actor, b.Target, "start", at); !errors.Is(e, windowsaction.ErrUnavailable) {
		t.Fatal("new job after intervention", e)
	}
}

func TestWindowsServiceActionSetupInspectionReadOnlyAndFenced(t *testing.T) {
	f, s, path, snap, cert := activeWindowsStore(t, "tls")
	at := time.Unix(testNow+10, 0).UTC()
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	inspection, e := InspectWindowsServiceActionSetup(context.Background(), path, f.issuerDER, snap.Approval.DeviceID, at)
	if e != nil || inspection.Status != "absent" || inspection.Config != f.config {
		t.Fatal("read-only inspection", e)
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection changed database")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{95}, 32))
	pub := key.Public().(ed25519.PublicKey)
	binding := windowsaction.Binding{ManagerID: snap.Binding.InstanceID, EndpointID: snap.Approval.DeviceID, IncarnationDigest: "sha256:" + cert.CertificateHash(), KeyID: windowsaction.Digest(pub), InstallationID: "broker_" + strings.Repeat("1", 32), GrantDigest: windowsaction.Digest([]byte("grant")), Target: "FixtureService", TargetDigest: windowsaction.Digest([]byte("config"))}
	s, e = Open(path, f.config, f.issuerDER)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SetupWindowsServiceActionsCreateOnly(context.Background(), pub, binding, at); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	inspection, e = InspectWindowsServiceActionSetup(context.Background(), path, f.issuerDER, snap.Approval.DeviceID, at)
	if e != nil || inspection.Status != "fenced" || !bytes.Equal(inspection.PublicKey, pub) {
		t.Fatal("used inspection", e)
	}
}
