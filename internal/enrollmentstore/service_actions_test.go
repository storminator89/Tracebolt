package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionhelper"
	"localrmm/internal/actionjob"
	"localrmm/internal/actionpermit"
	"localrmm/internal/actionstate"
	"localrmm/internal/enrollmentstate"
	"strings"
	"sync"
	"testing"
	"time"
)

func actionFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, ed25519.PrivateKey, time.Time) {
	t.Helper()
	f, s, path, snap, cert, at := journalFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	pub := key.Public().(ed25519.PublicKey)
	ctx := context.Background()
	if e := s.OpenServiceActions(ctx, pub); e == nil {
		t.Fatal("missing schema was accepted")
	}
	if e := s.InitializeServiceActions(ctx, pub); e != nil {
		t.Fatal(e)
	}
	if e := s.InitializeServiceActionIdentity(ctx, pub, snap.Approval.DeviceID, at); e != nil {
		t.Fatal(e)
	}
	if e := s.InitializeServiceActionIdentity(ctx, pub, snap.Approval.DeviceID, at); e == nil {
		t.Fatal("reinitialized row")
	}
	c := actionhelper.Capabilities{Version: "tracebolt.action-capabilities.v1", Enabled: true, ManagerID: s.Config().Binding.InstanceID, KeyID: actionpermit.Digest(pub), EndpointID: snap.Approval.DeviceID, IncarnationDigest: "sha256:" + cert.CertificateHash(), RootPolicyDigest: actionpermit.Digest([]byte("policy")), TransportProfile: actionhelper.DisposableHTTPTest, HTTPTestAcknowledged: true, CapturedAt: at.Unix(), MaxLifetimeSeconds: 60, Services: []actionhelper.CapabilityService{{Unit: "fixture.service", UnitPolicyDigest: actionpermit.Digest([]byte("unit"))}}}
	if s.Config().Binding.Profile == "tls" {
		c.TransportProfile = actionhelper.ProductionTLS
		c.HTTPTestAcknowledged = false
	}
	if e := s.ReportServiceActions(ctx, pub, snap.InvitationID, cert.CertificateHash(), c, at); e != nil {
		t.Fatal(e)
	}
	return f, s, path, snap, key, at
}
func actionSigner(key ed25519.PrivateKey) func(actionpermit.Permit) ([]byte, error) {
	return func(p actionpermit.Permit) ([]byte, error) {
		b, e := actionpermit.SigningMessage(p)
		if e != nil {
			return nil, e
		}
		return actionpermit.Encode(p, ed25519.Sign(key, b))
	}
}
func actionApprove(t *testing.T, s *Store, snap enrollmentstate.Snapshot, key ed25519.PrivateKey, at time.Time) actionjob.Job {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)
	ctx := context.Background()
	r, e := s.ServiceActionView(ctx, pub, snap.Approval.DeviceID, at)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.PreviewServiceAction(ctx, pub, snap.Approval.DeviceID, "action_"+strings.Repeat("a", 32), "operator_"+strings.Repeat("b", 32), "fixture.service", r.Capabilities.TransportProfile, at)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.ApproveServiceAction(ctx, pub, snap.Approval.DeviceID, r.Preview.ID, r.Preview.Digest, r.Preview.ActorID, r.Preview.TransportProfile, at.Add(time.Second), actionSigner(key))
	if e != nil {
		t.Fatal(e)
	}
	return r.Jobs[0]
}
func actionRecordBytes(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var b []byte
	if e := s.db.QueryRow(`SELECT body FROM enrollment_service_action_records WHERE invitation_id=?`, id).Scan(&b); e != nil {
		t.Fatal(e)
	}
	return b
}
func TestServiceActionsDurableClaimAndStatusAfterReopen(t *testing.T) {
	f, s, path, snap, key, at := actionFixture(t)
	ctx := context.Background()
	pub := key.Public().(ed25519.PublicKey)
	j := actionApprove(t, s, snap, key, at)
	other := f.open(t, path)
	defer other.Close()
	d, e := other.PeekServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, at.Add(2*time.Second))
	if e != nil || d.Identity != j.Identity() {
		t.Fatal(e)
	}
	g, e := other.ClaimServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, j.Preview.TransportProfile, d.Identity, at.Add(2*time.Second))
	if e != nil || len(g.Envelope) == 0 {
		t.Fatal(e)
	}
	g, e = s.ClaimServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, j.Preview.TransportProfile, d.Identity, at.Add(3*time.Second))
	if !errors.Is(e, actionjob.ErrConsumed) || len(g.Envelope) != 0 {
		t.Fatal("duplicate grant", e)
	}
	x := actionhelper.Result{JobID: j.Preview.ID, Sequence: j.Preview.Sequence, EnvelopeDigest: j.Identity().EnvelopeDigest, Phase: actionstate.NotStarted, ConsumedAt: at.Add(2 * time.Second).UnixMicro(), TransitionAt: at.Add(3 * time.Second).UnixMicro(), Reason: actionstate.ReasonInactive}
	if e = s.AcceptServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, x, at.Add(4*time.Second)); e != nil {
		t.Fatal(e)
	}
	before := actionRecordBytes(t, s, snap.InvitationID)
	if e = other.AcceptServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, x, at.Add(5*time.Second)); e != nil || !bytes.Equal(before, actionRecordBytes(t, s, snap.InvitationID)) {
		t.Fatal("receipt retry mutated", e)
	}
}
func TestServiceActionsConcurrentClaimSingleGrant(t *testing.T) {
	f, s, path, snap, key, at := actionFixture(t)
	j := actionApprove(t, s, snap, key, at)
	other := f.open(t, path)
	defer other.Close()
	var wg sync.WaitGroup
	grants := make(chan actionjob.Grant, 2)
	for _, store := range []*Store{s, other} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			g, _ := store.ClaimServiceAction(context.Background(), key.Public().(ed25519.PublicKey), snap.InvitationID, snap.Issuance.CertificateHash, j.Preview.TransportProfile, j.Identity(), at.Add(2*time.Second))
			grants <- g
		}(store)
	}
	wg.Wait()
	close(grants)
	n := 0
	for g := range grants {
		if len(g.Envelope) > 0 {
			n++
		}
	}
	if n != 1 {
		t.Fatal("grants", n)
	}
}
func TestServiceActionsLostIdentityNeverRecreated(t *testing.T) {
	_, s, _, snap, key, at := actionFixture(t)
	ctx := context.Background()
	pub := key.Public().(ed25519.PublicKey)
	j := actionApprove(t, s, snap, key, at)
	var old actionjob.Record
	json.Unmarshal(actionRecordBytes(t, s, snap.InvitationID), &old)
	if _, e := s.db.Exec(`DELETE FROM enrollment_service_action_records WHERE invitation_id=?`, snap.InvitationID); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ServiceActionView(ctx, pub, snap.Approval.DeviceID, at.Add(2*time.Second)); e == nil {
		t.Fatal("view invented identity")
	}
	if e := s.ReportServiceActions(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, *old.Capabilities, at.Add(2*time.Second)); e == nil {
		t.Fatal("report recreated identity")
	}
	if _, e := s.PreviewServiceAction(ctx, pub, snap.Approval.DeviceID, j.Preview.ID, j.Preview.ActorID, j.Preview.Plan.Unit, j.Preview.TransportProfile, at.Add(2*time.Second)); e == nil {
		t.Fatal("preview recreated identity")
	}
	if _, e := s.ApproveServiceAction(ctx, pub, snap.Approval.DeviceID, j.Preview.ID, j.Preview.Digest, j.Preview.ActorID, j.Preview.TransportProfile, at.Add(2*time.Second), actionSigner(key)); e == nil {
		t.Fatal("approval recreated identity")
	}
	if g, e := s.ClaimServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, j.Preview.TransportProfile, j.Identity(), at.Add(2*time.Second)); e == nil || len(g.Envelope) > 0 {
		t.Fatal("claim recreated identity")
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM enrollment_service_action_records`).Scan(&n)
	if n != 0 {
		t.Fatal("lost row restored")
	}
}
func TestServiceActionObservedExpiryCannotRevive(t *testing.T) {
	for _, which := range []string{"view", "peek", "claim"} {
		t.Run(which, func(t *testing.T) {
			_, s, _, snap, key, at := actionFixture(t)
			j := actionApprove(t, s, snap, key, at)
			ctx := context.Background()
			pub := key.Public().(ed25519.PublicKey)
			late := j.Deadline().Add(time.Second)
			switch which {
			case "view":
				if _, e := s.ServiceActionView(ctx, pub, snap.Approval.DeviceID, late); e != nil {
					t.Fatal(e)
				}
			case "peek":
				if _, e := s.PeekServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, late); !errors.Is(e, actionjob.ErrNotFound) {
					t.Fatal(e)
				}
			case "claim":
				if _, e := s.ClaimServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, j.Preview.TransportProfile, j.Identity(), late); !errors.Is(e, actionjob.ErrExpired) {
					t.Fatal(e)
				}
			}
			if g, e := s.ClaimServiceAction(ctx, pub, snap.InvitationID, snap.Issuance.CertificateHash, j.Preview.TransportProfile, j.Identity(), at.Add(2*time.Second)); e == nil || len(g.Envelope) != 0 {
				t.Fatal("expired grant revived")
			}
		})
	}
}
func TestServiceActionCanceledPersistenceReleasesNoApproval(t *testing.T) {
	_, s, _, snap, key, at := actionFixture(t)
	pub := key.Public().(ed25519.PublicKey)
	r, e := s.ServiceActionView(context.Background(), pub, snap.Approval.DeviceID, at)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.PreviewServiceAction(context.Background(), pub, snap.Approval.DeviceID, "action_"+strings.Repeat("c", 32), "operator_"+strings.Repeat("d", 32), "fixture.service", r.Capabilities.TransportProfile, at)
	if e != nil {
		t.Fatal(e)
	}
	p := *r.Preview
	before := actionRecordBytes(t, s, snap.InvitationID)
	ctx, cancel := context.WithCancel(context.Background())
	sign := actionSigner(key)
	out, e := s.ApproveServiceAction(ctx, pub, snap.Approval.DeviceID, p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(time.Second), func(p actionpermit.Permit) ([]byte, error) { raw, e := sign(p); cancel(); return raw, e })
	if e == nil || len(out.Jobs) > 0 {
		t.Fatal("uncommitted approval escaped")
	}
	if !bytes.Equal(before, actionRecordBytes(t, s, snap.InvitationID)) {
		t.Fatal("canceled approval persisted")
	}
}
func TestServiceActionPreviewExpiryCannotReviveAfterFailedApproval(t *testing.T) {
	_, s, _, snap, key, at := actionFixture(t)
	pub := key.Public().(ed25519.PublicKey)
	ctx := context.Background()
	r, e := s.ServiceActionView(ctx, pub, snap.Approval.DeviceID, at)
	if e != nil {
		t.Fatal(e)
	}
	r, e = s.PreviewServiceAction(ctx, pub, snap.Approval.DeviceID, "action_"+strings.Repeat("c", 32), "operator_"+strings.Repeat("d", 32), "fixture.service", r.Capabilities.TransportProfile, at)
	if e != nil {
		t.Fatal(e)
	}
	p := *r.Preview
	if _, e = s.ApproveServiceAction(ctx, pub, snap.Approval.DeviceID, p.ID, p.Digest, p.ActorID, p.TransportProfile, p.ExpiresAt, actionSigner(key)); !errors.Is(e, actionjob.ErrExpired) {
		t.Fatal(e)
	}
	if r, e = s.ApproveServiceAction(ctx, pub, snap.Approval.DeviceID, p.ID, p.Digest, p.ActorID, p.TransportProfile, at.Add(time.Second), actionSigner(key)); e == nil || len(r.Jobs) > 0 {
		t.Fatal("preview revived")
	}
}
func TestServiceActionRevocationKeepsJobHistoryAndDeniesGrant(t *testing.T) {
	_, s, _, snap, key, at := actionFixture(t)
	j := actionApprove(t, s, snap, key, at)
	ctx := context.Background()
	revoke := control(snap, 7)
	revoke.Now = at.Add(2 * time.Second).Unix()
	if _, e := s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	before := actionRecordBytes(t, s, snap.InvitationID)
	if g, e := s.ClaimServiceAction(ctx, key.Public().(ed25519.PublicKey), snap.InvitationID, snap.Issuance.CertificateHash, j.Preview.TransportProfile, j.Identity(), at.Add(3*time.Second)); e == nil || len(g.Envelope) > 0 {
		t.Fatal("revoked grant released")
	}
	if !bytes.Equal(before, actionRecordBytes(t, s, snap.InvitationID)) {
		t.Fatal("revocation reset history")
	}
}
