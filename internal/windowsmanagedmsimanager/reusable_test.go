package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"strings"
	"testing"
)

func reusableManagerFixture(t *testing.T) (*Manager, *fleetMemoryStore, ed25519.PrivateKey, string, *int64, string) {
	t.Helper()
	dir, spool := protectedSpoolFixture(t)
	m, s, key, actor, now := managerFixture(t)
	g := s.r.Grant
	g.Version = msi.ReusableGrantVersion
	g.ReusableAcknowledged = true
	g.MutationPlanDigest = msi.Digest([]byte("fresh plan"))
	g.PeerBindingDigest = msi.Digest([]byte("peer"))
	var e error
	s.r, e = msi.NewRecord(g, s.r.PublicKey, s.r.ExecutorPublicKey, *now)
	if e != nil {
		t.Fatal(e)
	}
	store := &fleetMemoryStore{members: map[string]*memoryStore{m.binding.DeviceID: s}, artifact: msi.ArtifactRecord{Version: msi.ReusableArtifactRecordVersion, ClockFloor: *now}, now: now}
	a, e := newArtifactManager(context.Background(), store, s.r.PublicKey, spool, m.now, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	a.deliveryAllowed = func(id string) bool { return id == actor }
	m.store = store
	m.spool = spool
	m.artifact = a
	return m, store, key, actor, now, dir
}
func reusableManagerUpload(t *testing.T, m *Manager, actor string, tag byte) string {
	t.Helper()
	data := inertArtifact()
	data[len(data)-1] = tag
	sel := managerSelection()
	sel.SHA256 = msi.Digest(data)
	sel.Name = "Reviewed fixture " + string([]byte{tag})
	ctx := context.Background()
	if e := m.artifact.ReserveReusableUpload(ctx, actor, sel, msi.Digest([]byte("native review")), "unverified", msi.Digest([]byte("publisher evidence"))); e != nil {
		t.Fatal("reserve", e)
	}
	if e := m.artifact.Upload(ctx, actor, UploadChunk{PackageDigest: sel.SHA256, Digest: msi.Digest(data), Data: data}); e != nil {
		t.Fatal("upload", e)
	}
	if e := m.artifact.CompleteUpload(ctx, actor); e != nil {
		t.Fatal("complete", e)
	}
	r, e := m.artifact.read(ctx)
	if e != nil {
		t.Fatal(e)
	}
	return msi.ArtifactIdentity(*r.Artifact)
}
func reusableManagerReport(t *testing.T, m *Manager, key ed25519.PrivateKey, raw []byte, kind string, now int64) []byte {
	t.Helper()
	p, e := msi.VerifyPermit(raw, m.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	r := msi.Report{Version: p.Version, JobSequence: p.JobSequence, Kind: kind, Binding: p.Binding, TransferID: p.TransferID, PermitDigest: msi.Digest(raw), Package: p.Package, NativeAcceptanceDigest: p.NativeAcceptanceDigest, CapturedAt: now, Offset: p.Package.Size}
	switch kind {
	case "delivery":
		r.State = "imported"
	case "readiness":
		r.State = "ready"
		r.Readiness = &msi.Readiness{Selection: p.Package, CapturedAt: now, PackageVerified: msi.Yes, MachineAbsent: msi.Yes, InstallerBusy: msi.No, NativeAcceptance: msi.Yes, PackageReviewAccepted: msi.Yes, MaintenanceWindowEnd: p.MaintenanceUntil}
	case "result":
		r.State = "succeeded"
		r.Result = &msi.Result{JobID: "software_" + strings.TrimPrefix(p.TransferID, "transfer_"), EnvelopeDigest: msi.Digest(raw), Attempted: true, Outcome: "succeeded", ReturnCodeKnown: true, RegistrationVerified: msi.Yes, CompletedAt: now}
	case "mutation":
		r.State = "idle"
		r.Mutation = &fence.Status{Active: true, Phase: "idle", Revision: p.JobSequence * 10, Retained: 0}
	case "retired":
		r.State = "retired"
		r.Retirement = &msi.RetirementEvidence{ResultDigest: p.RetireResultDigest, ReleaseDigest: msi.Digest([]byte("exact saved release")), CustodyDigest: msi.Digest([]byte("exact original custody"))}
	}
	out, e := msi.SignReport(r, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Report(context.Background(), out); e != nil {
		t.Fatal(kind, e)
	}
	return out
}
func TestReusableManagerDifferentPackageAfterReviewedRetirementRestart(t *testing.T) {
	m, store, key, actor, now, dir := reusableManagerFixture(t)
	ctx := context.Background()
	expiry := store.members[m.binding.DeviceID].r.Grant.ExpiresAt
	y := addReusableManagerTarget(t, m, store)
	defer y.Close()
	var oldInstall, oldRetired []byte
	for job := 1; job <= 2; job++ {
		art := reusableManagerUpload(t, m, actor, byte('A'+job-1))
		if poll, e := y.Poll(ctx); e != nil || len(poll.Permit) != 0 {
			t.Fatal("unselected Y received work", e)
		}
		v, e := m.View(ctx)
		if e != nil || v.State != "uploaded" || *v.ArtifactID != art || job == 2 && len(v.History) != 1 {
			t.Fatal("next projection", v.State, e)
		}
		transfer := "transfer_" + strings.Repeat(string([]byte{'7' + byte(job)}), 32)
		if e = m.DeliverArtifact(ctx, actor, transfer, true, art, msi.BindingDigest(m.binding)); e != nil {
			t.Fatal("deliver", e)
		}
		if job == 2 {
			if e = m.Report(ctx, oldRetired); e != nil {
				t.Fatal("saved retirement starved new job", e)
			}
		}
		poll, e := m.Poll(ctx)
		if e != nil {
			t.Fatal(e)
		}
		p, _ := msi.VerifyPermit(poll.Permit, m.key.Public().(ed25519.PublicKey))
		if p.JobSequence != uint64(job) {
			t.Fatal("job sequence")
		}
		reusableManagerReport(t, m, key, poll.Permit, "delivery", *now)
		delivery := poll.Permit
		if e = m.Review(ctx, actor, true, true, true, true); e != nil {
			t.Fatal("review", e)
		}
		poll, e = m.Poll(ctx)
		if e != nil {
			t.Fatal(e)
		}
		ready := reusableManagerReport(t, m, key, poll.Permit, "readiness", *now)
		reusableManagerReport(t, m, key, delivery, "mutation", *now)
		if e = m.Approve(ctx, actor, msi.Digest(ready), true); e != nil {
			t.Fatal("approve", e)
		}
		poll, e = m.Poll(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if job == 1 {
			oldInstall = bytes.Clone(poll.Permit)
		}
		result := reusableManagerReport(t, m, key, poll.Permit, "result", *now)
		if e = m.DeliverArtifact(ctx, actor, "transfer_"+strings.Repeat("f", 32), true, art, msi.BindingDigest(m.binding)); e == nil {
			t.Fatal("advanced without reviewed retirement")
		}
		if e = m.artifact.RetireArtifact(ctx, actor, art, true); e == nil {
			t.Fatal("deleted assigned unretired payload")
		}
		if e = m.Retire(ctx, actor, msi.Digest(result), true); e != nil {
			t.Fatal("retire", e)
		}
		poll, e = m.Poll(ctx)
		if e != nil {
			t.Fatal(e)
		}
		retired := reusableManagerReport(t, m, key, poll.Permit, "retired", *now)
		if job == 1 {
			oldRetired = bytes.Clone(retired)
		}
		if e = m.artifact.RetireArtifact(ctx, actor, art, true); e != nil {
			t.Fatal("artifact retire", e)
		}
		if job == 1 {
			m.Close()
			spool, e := OpenSpool(dir)
			if e != nil {
				t.Fatal(e)
			}
			a, e := newArtifactManager(ctx, store, store.members[m.binding.DeviceID].r.PublicKey, spool, m.now, func() error { return nil })
			if e != nil {
				t.Fatal(e)
			}
			a.deliveryAllowed = func(id string) bool { return id == actor }
			m, e = open(ctx, store, m.binding, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32)), spool, m.now, func() error { return nil }, a)
			if e != nil {
				t.Fatal("restart", e)
			}
			m.ConfigureOperatorPolicy(func(id string) bool { return id == actor }, func(id string) bool { return id == actor })
			*now += 1
		}
	}
	r := store.members[m.binding.DeviceID].r
	if r.Grant.ExpiresAt != expiry || r.Jobs.Sequence != 2 || r.Jobs.RetiredFloor != 1 {
		t.Fatal("grant/floor changed")
	}
	if e := m.CheckRelease(ctx, oldInstall, ""); e == nil {
		t.Fatal("old job authority released")
	}
	// Literal legacy bytes remain absent of all v3 state.
	legacy := managerSelection()
	raw, _ := json.Marshal(legacy)
	if bytes.Contains(raw, []byte("publisher")) {
		t.Fatal("prepared selection changed")
	}
}

func addReusableManagerTarget(t *testing.T, m *Manager, s *fleetMemoryStore) *Manager {
	t.Helper()
	g := s.members[m.binding.DeviceID].r.Grant
	g.Binding.DeviceID = "agent_" + strings.Repeat("a", 32)
	g.Binding.ExecutorID = "executor_" + strings.Repeat("b", 32)
	g.Binding.DeliveryGrantID = "grant_" + strings.Repeat("c", 32)
	g.Binding.InstallGrantID = "grant_" + strings.Repeat("d", 32)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	g.Binding.ExecutorKeyID = msi.Digest(key.Public().(ed25519.PublicKey))
	r, e := msi.NewRecord(g, m.key.Public().(ed25519.PublicKey), key.Public().(ed25519.PublicKey), *s.now)
	if e != nil {
		t.Fatal(e)
	}
	c := s.members[m.binding.DeviceID].current
	c.Binding = g.Binding
	s.members[g.Binding.DeviceID] = &memoryStore{r: r, current: c, now: s.now}
	y, e := open(context.Background(), s, g.Binding, m.key, m.spool, m.now, m.configurationCheck, m.artifact)
	if e != nil {
		t.Fatal(e)
	}
	y.ConfigureOperatorPolicy(m.deliveryAllowed, m.installAllowed)
	return y
}
func TestReusableSharedRetirementKeepsOtherUnresolvedTarget(t *testing.T) {
	m, s, _, actor, _, _ := reusableManagerFixture(t)
	y := addReusableManagerTarget(t, m, s)
	ctx := context.Background()
	art := reusableManagerUpload(t, m, actor, 'A')
	if e := y.DeliverArtifact(ctx, actor, "transfer_"+strings.Repeat("e", 32), true, art, msi.BindingDigest(y.binding)); e != nil {
		t.Fatal(e)
	}
	if e := m.artifact.RetireArtifact(ctx, actor, art, true); e == nil {
		t.Fatal("one target discarded another target's unresolved bytes")
	}
	r, e := m.artifact.read(ctx)
	if e != nil || r.RetirementStarted || r.Retired {
		t.Fatal("failed cleanup consumed global custody", e)
	}
	if s.members[m.binding.DeviceID].r.TransferID != "" {
		t.Fatal("unselected target gained a job")
	}
}
