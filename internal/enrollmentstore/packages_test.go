package enrollmentstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/linuxpackages"
	"path/filepath"
	"testing"
	"time"
)

func packageFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, enrollmentcrypto.VerifiedCertificate) {
	t.Helper()
	f := newFixture(t)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	f.challenge.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	f.config.RecordLimit = 25
	f.config.InvitationLimit = 25
	f.config.PendingLimit = 25
	path := filepath.Join(t.TempDir(), "private", "packages.db")
	s := f.open(t, path)
	state, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	state, e := s.CommitIssued(context.Background(), control(state, 5), cert)
	if e != nil {
		t.Fatal(e)
	}
	c := control(state, 6)
	state, e = s.Activate(context.Background(), c, f.activation(t, cert, c))
	if e != nil {
		t.Fatal(e)
	}
	return f, s, path, state, cert
}
func packageFrameFixture(t *testing.T, sequence uint64, at time.Time, available bool) []byte {
	t.Helper()
	raw, op := operationalFrame(t, sequence, at, true)
	var frame lanstore.Frame
	if json.Unmarshal(raw, &frame) != nil {
		t.Fatal("frame fixture")
	}
	snapshot := linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope, GenerationID: op.GenerationID, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Inventory: linuxpackages.Inventory{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing, Items: []linuxpackages.PackageRow{}}}
	if available {
		id, version, codename := "debian", "13", "trixie"
		n := uint64(1)
		snapshot.Release = linuxpackages.ReleaseObservation{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Fields: linuxpackages.ReleaseFields{ID: &id, VersionID: &version, VersionCodename: &codename}}
		snapshot.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Complete: true, CountExact: true, ObservedCount: &n, InstalledCount: &n, Items: []linuxpackages.PackageRow{{Name: "fixture-package", Version: "1.0-1", Architecture: "amd64", SourcePackage: "fixture-source", SourceVersion: "1.0-1", SourceMapping: "source-field", InstallState: "installed"}}}
	}
	frame.SchemaVersion = lanstore.FramePackagesVersion
	frame.Packages = &snapshot
	raw, e := json.Marshal(frame)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(raw, at); e != nil {
		t.Fatal("package frame fixture", e)
	}
	return raw
}
func TestPackageLatestOnlyReplayReopenRevocationAndExpiry(t *testing.T) {
	f, s, path, identity, cert := packageFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	first := packageFrameFixture(t, 1, at, true)
	receipt, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), first, at)
	if e != nil {
		t.Fatal(e)
	}
	view, e := s.PackageView(ctx, identity.Approval.DeviceID, at)
	if e != nil || view.Status != "fresh" || view.Snapshot == nil || view.Snapshot.Inventory.InstalledCount == nil || *view.Snapshot.Inventory.InstalledCount != 1 {
		t.Fatal("missing package view", e)
	}
	*view.Snapshot.Release.Fields.ID = "changed"
	view.Snapshot.Inventory.Items[0].Name = "changed"
	*view.Snapshot.Inventory.InstalledCount = 999
	again, e := s.PackageView(ctx, identity.Approval.DeviceID, at)
	if e != nil || *again.Snapshot.Release.Fields.ID != "debian" || again.Snapshot.Inventory.Items[0].Name != "fixture-package" || *again.Snapshot.Inventory.InstalledCount != 1 {
		t.Fatal("mutable package view aliased")
	}
	later := at.Add(time.Second)
	second := packageFrameFixture(t, 2, later, false)
	if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), second, later); e != nil {
		t.Fatal(e)
	}
	view, e = s.PackageView(ctx, identity.Approval.DeviceID, later)
	if e != nil || view.Snapshot == nil || view.Snapshot.Inventory.Quality != linuxpackages.Unknown || view.Snapshot.Inventory.InstalledCount != nil || len(view.Snapshot.Inventory.Items) != 0 {
		t.Fatal("package facts retained across unknown generation", e)
	}
	s.Close()
	s = f.open(t, path)
	duplicate, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), second, later.Add(time.Minute))
	if e != nil || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(later) || duplicate.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("retry changed package receipt", e)
	}
	stale, e := s.PackageView(ctx, identity.Approval.DeviceID, later.Add(3*time.Minute))
	if e != nil || stale.Status != "stale" {
		t.Fatal("package age", e)
	}
	expired, e := s.PackageView(ctx, identity.Approval.DeviceID, later.Add(25*time.Hour))
	if e != nil || expired.Snapshot != nil || expired.Status == "fresh" {
		t.Fatal("package view expiry", e)
	}
	if e = s.transact(ctx, func(tx *transaction) error {
		if !bytes.Equal(tx.credentials[identity.InvitationID].Frame, second) {
			t.Fatal("expiry erased exact replay frame")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	current, e := s.Get(ctx, identity.InvitationID)
	if e != nil {
		t.Fatal(e)
	}
	revokeControl := control(current, 19)
	revokeControl.Now = later.Add(2 * time.Second).Unix()
	if _, e = s.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revokeControl, State: enrollmentstate.Revoked}); e != nil {
		t.Fatal(e)
	}
	revoked, e := s.PackageView(ctx, identity.Approval.DeviceID, later)
	if e != nil || revoked.Status != "revoked" {
		t.Fatal("revoked package view", e)
	}
	if _, e = s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), second, later); e == nil {
		t.Fatal("revoked exact retry accepted")
	}
}
func TestPackageProfileCannotAdoptLegacyFramesOrStores(t *testing.T) {
	_, s, _, identity, cert := packageFixture(t)
	ctx := context.Background()
	at := time.Unix(testNow+10, 0).UTC()
	old, _ := operationalFrame(t, 1, at, true)
	if _, e := s.SaveObservation(ctx, identity.InvitationID, cert.CertificateHash(), old, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("old operations adopted package profile", e)
	}
	f, legacy, path, legacyID, legacyCert := operationalFixture(t)
	packages := packageFrameFixture(t, 1, at, true)
	if _, e := legacy.SaveObservation(ctx, legacyID.InvitationID, legacyCert.CertificateHash(), packages, at); !errors.Is(e, enrollmentstate.ErrProof) {
		t.Fatal("package scope accepted by original profile", e)
	}
	legacy.Close()
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfilePackages
	if adopted, e := Open(path, f.config, f.issuerDER); e == nil {
		adopted.Close()
		t.Fatal("old store adopted package binding")
	}
}
func TestPackageFrameValidationCacheDetachesEveryMutableMember(t *testing.T) {
	at := time.Unix(testNow+10, 0).UTC()
	raw := packageFrameFixture(t, 1, at, true)
	tx := &transaction{}
	first, e := tx.validateFrame(raw, at)
	if e != nil {
		t.Fatal(e)
	}
	*first.Packages.Release.Fields.ID = "changed"
	*first.Packages.Release.Fields.VersionID = "changed"
	*first.Packages.Release.Fields.VersionCodename = "changed"
	*first.Packages.Inventory.ObservedCount = 4
	*first.Packages.Inventory.InstalledCount = 3
	first.Packages.Inventory.Items[0].Name = "changed"
	again, e := tx.validateFrame(raw, at)
	if e != nil || *again.Packages.Release.Fields.ID != "debian" || *again.Packages.Release.Fields.VersionID != "13" || *again.Packages.Release.Fields.VersionCodename != "trixie" || *again.Packages.Inventory.ObservedCount != 1 || *again.Packages.Inventory.InstalledCount != 1 || again.Packages.Inventory.Items[0].Name != "fixture-package" {
		t.Fatal("cached package parse was mutable")
	}
}
