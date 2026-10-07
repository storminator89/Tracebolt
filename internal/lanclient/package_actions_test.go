package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/packagehelper"
	"localrmm/internal/packagepermit"
	"localrmm/internal/packageupdate"
	"localrmm/internal/packagewire"
	"testing"
	"time"
)

type packageFakeHelper struct {
	caps                     packagehelper.Capabilities
	snapshot                 packagehelper.Snapshot
	submits, statuses, reads int
	submitError, statusError error
	capHook                  func(int)
}

func (h *packageFakeHelper) Capabilities(context.Context) (packagehelper.Capabilities, error) {
	h.reads++
	if h.capHook != nil {
		h.capHook(h.reads)
	}
	return h.caps, nil
}
func (h *packageFakeHelper) Submit(context.Context, []byte) (packagehelper.Snapshot, error) {
	h.submits++
	return h.snapshot, h.submitError
}
func (h *packageFakeHelper) Status(context.Context, string) (packagehelper.Snapshot, error) {
	h.statuses++
	return h.snapshot, h.statusError
}

type packageFixture struct {
	s                         *packageSender
	helper                    *packageFakeHelper
	local                     packageLocal
	at                        time.Time
	delivery                  packagewire.Delivery
	grant                     packagewire.Grant
	claimed, current          bool
	claims, reports, requests int
	claimError                error
	localError                error
	hook                      func(string)
}

func packageSenderFixture(t *testing.T) *packageFixture {
	t.Helper()
	f := &packageFixture{at: time.Unix(1700000000, 0).UTC(), current: true}
	d := actionpermit.Digest([]byte("scope"))
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{39}, 32))
	m := Material{loaded: true, binding: actionpermit.Digest([]byte("material"))[7:], config: Config{SchemaVersion: CompleteConfigVersion, CollectionProfile: enrollmentcrypto.CollectionProfileComplete, Profile: "tls", ManagerOrigin: "https://manager.test", AgentID: "agent_11111111111111111111111111111111"}, certificate: tls.Certificate{Certificate: [][]byte{[]byte("synthetic certificate")}}}
	f.local = packageLocal{revision: d, policy: PackageClientPolicy{Version: PackageClientPolicyVersion, Enabled: true, SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, ManagerID: "manager_11111111111111111111111111111111", EndpointID: m.config.AgentID, IncarnationDigest: "sha256:" + journalLeaf(m), KeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey)), RootPolicyDigest: d, TransportProfile: "production-tls", AgentUID: 1234, AgentGID: 1234}}
	p := f.local.policy
	caps := packagehelper.Capabilities{Version: packagehelper.CapabilitiesVersion, Enabled: true, ManagerID: p.ManagerID, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, KeyID: p.KeyID, RootPolicyDigest: d, TransportProfile: p.TransportProfile, CapturedAt: f.at.Unix(), Allowed: []packagepermit.Selection{{Name: "sample-bin", Architecture: "amd64"}}}
	permit := packagepermit.Permit{Version: packagepermit.Version, Action: packagepermit.Prepare, ManagerID: p.ManagerID, EndpointID: p.EndpointID, IncarnationDigest: p.IncarnationDigest, KeyID: p.KeyID, RootPolicyDigest: p.RootPolicyDigest, JobID: "update_11111111111111111111111111111111", Sequence: 1, ActorID: "operator_11111111111111111111111111111111", IssuedAt: f.at.Unix(), NotBefore: f.at.Unix(), StartDeadline: f.at.Unix() + 120, Selection: caps.Allowed}
	raw, e := packagepermit.Sign(context.Background(), permit, key)
	if e != nil {
		t.Fatal(e)
	}
	id := packagewire.Identity{JobID: permit.JobID, Sequence: 1, Kind: packagepermit.Prepare, EnvelopeDigest: actionpermit.Digest(raw)}
	f.grant = packagewire.Grant{Identity: id, Envelope: raw}
	f.delivery = packagewire.Delivery{Identity: id, State: "pending", StartDeadline: permit.StartDeadline}
	f.helper = &packageFakeHelper{caps: caps, snapshot: packagehelper.Snapshot{Version: packagehelper.SnapshotVersion, JobID: id.JobID, Sequence: 1, PreparationEnvelopeDigest: id.EnvelopeDigest, State: packageupdate.Preparing, Results: []packageupdate.Result{}, UpdatedAt: f.at.Unix()}}
	f.s = &packageSender{material: m, helper: f.helper, now: func() time.Time { return f.at }, current: func(Material) bool { return f.current }, local: func(Material) (packageLocal, error) { return f.local, f.localError }}
	f.s.exchange = func(_ context.Context, path string, seq uint64, raw []byte) ([]byte, int, error) {
		f.requests++
		if f.hook != nil {
			f.hook(path)
		}
		switch path {
		case packagewire.CapabilitiesPath:
			if _, e := packagewire.DecodeCapabilities(raw); e != nil {
				t.Fatal(e)
			}
			return []byte("{}"), 200, nil
		case packagewire.PeekPath:
			d := f.delivery
			if f.claimed {
				d.State = "claimed"
			}
			out, e := packagewire.EncodeDelivery(d)
			return out, 200, e
		case packagewire.ClaimPath:
			f.claims++
			if f.claimed {
				return nil, 409, nil
			}
			f.claimed = true
			if f.claimError != nil {
				return nil, 0, f.claimError
			}
			out, e := packagewire.EncodeGrant(f.grant)
			return out, 200, e
		case packagewire.ResultPath:
			f.reports++
			if _, e := packagewire.DecodeResult(raw); e != nil {
				t.Fatal(e)
			}
			return []byte("{}"), 200, nil
		}
		t.Fatal(path)
		return nil, 0, nil
	}
	return f
}
func TestPackageSenderLostDeliveryIsStatusOnly(t *testing.T) {
	for _, which := range []string{"claim", "submit", "success"} {
		t.Run(which, func(t *testing.T) {
			f := packageSenderFixture(t)
			if which == "claim" {
				f.claimError = errors.New("lost response")
				f.helper.statusError = errors.New("not found")
			}
			if which == "submit" {
				f.helper.submitError = errors.New("lost response")
			}
			got := f.s.Run(context.Background())
			if which == "success" && got != "reported" || which != "success" && got != "outcome_unknown" {
				t.Fatal(got)
			}
			for i := 0; i < 3; i++ {
				f.s.Run(context.Background())
			}
			want := 1
			if which == "claim" {
				want = 0
			}
			if f.claims != 1 || f.helper.submits != want || f.helper.statuses != 3 {
				t.Fatal("replay", f.claims, f.helper.submits, f.helper.statuses)
			}
		})
	}
}
func TestPackageSenderChecksRevocationAfterClaimAndSnapshotBinding(t *testing.T) {
	f := packageSenderFixture(t)
	f.hook = func(path string) {
		if path == packagewire.ClaimPath {
			f.local.revision = actionpermit.Digest([]byte("revoked"))
		}
	}
	if got := f.s.Run(context.Background()); got != "denied" || f.helper.submits != 0 {
		t.Fatal(got, f.helper.submits)
	}
	f = packageSenderFixture(t)
	f.helper.snapshot.PreparationEnvelopeDigest = actionpermit.Digest([]byte("other"))
	if got := f.s.Run(context.Background()); got != "denied" || f.reports != 0 {
		t.Fatal("wrong root result", got)
	}
	f = packageSenderFixture(t)
	f.localError = errPackageDisabled
	if got := f.s.Run(context.Background()); got != "disabled" || f.requests != 0 || f.helper.reads != 0 {
		t.Fatal("default-off performed I/O", got)
	}
}
func TestPackageSenderUnavailableCapabilityStillReadsClaimedStatus(t *testing.T) {
	f := packageSenderFixture(t)
	f.claimed = true
	f.helper.caps.Enabled = false
	f.at = f.at.Add(time.Hour)
	if got := f.s.Run(context.Background()); got != "reported" || f.helper.submits != 0 || f.helper.statuses != 1 {
		t.Fatal("historical custody gated on live admission", got)
	}
	f = packageSenderFixture(t)
	f.helper.caps.Enabled = false
	if got := f.s.Run(context.Background()); got != "helper_unavailable" || f.claims != 0 || f.helper.submits != 0 {
		t.Fatal(got)
	}
}
func TestPackageClientLocalScopeCannotBorrowServiceOrCollectionGrant(t *testing.T) {
	f := packageSenderFixture(t)
	p := f.local.policy
	if e := validatePackageLocal(p, f.s.material, 1234, 1234); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*PackageClientPolicy){func(p *PackageClientPolicy) { p.Version = ActionClientPolicyVersion }, func(p *PackageClientPolicy) { p.EndpointID = "agent_22222222222222222222222222222222" }, func(p *PackageClientPolicy) { p.TransportProfile = "disposable-http-test" }, func(p *PackageClientPolicy) { p.AgentUID = 0 }} {
		q := p
		change(&q)
		if validatePackageLocal(q, f.s.material, 1234, 1234) == nil {
			t.Fatal("unrelated scope accepted")
		}
	}
}

func TestWindowsInventorySenderCannotPollPackageActions(t *testing.T) {
	f := packageSenderFixture(t)
	f.s.material.config.SchemaVersion = WindowsInventoryConfigVersion
	f.s.material.config.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	localReads := 0
	f.s.local = func(Material) (packageLocal, error) { localReads++; return f.local, nil }
	if got := f.s.Run(context.Background()); got != "disabled" || localReads != 0 || f.helper.reads != 0 || f.requests != 0 {
		t.Fatal("Windows inventory entered Linux package pipeline", got, localReads, f.helper.reads, f.requests)
	}
}
