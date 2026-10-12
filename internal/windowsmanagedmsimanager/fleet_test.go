package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentstate"
	msi "localrmm/internal/windowsmanagedmsi"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fleetMemoryStore struct {
	members  map[string]*memoryStore
	artifact msi.ArtifactRecord
	now      *int64
}

func (s *fleetMemoryStore) WindowsManagedMSIEnrollmentBinding() enrollmentstate.Binding {
	for _, m := range s.members {
		return m.WindowsManagedMSIEnrollmentBinding()
	}
	return enrollmentstate.Binding{}
}
func (s *fleetMemoryStore) ReadRegisteredWindowsManagedMSI(ctx context.Context, b msi.Binding, k ed25519.PublicKey) (msi.Record, error) {
	m := s.members[b.DeviceID]
	if m == nil || b != m.r.Grant.Binding || !bytes.Equal(k, m.r.PublicKey) {
		return msi.Record{}, msi.ErrAuthority
	}
	return m.ReadRegisteredWindowsManagedMSI(ctx, b, k)
}
func (s *fleetMemoryStore) WindowsManagedMSITransaction(ctx context.Context, b msi.Binding, k ed25519.PublicKey, at time.Time, fn func(*msi.Record, msi.Current, time.Time) error) (msi.Record, time.Time, error) {
	m := s.members[b.DeviceID]
	if m == nil || b != m.r.Grant.Binding || m.current.Revoked {
		return msi.Record{}, at, msi.ErrAuthority
	}
	return m.WindowsManagedMSITransaction(ctx, b, k, at, fn)
}
func (s *fleetMemoryStore) ReadWindowsManagedMSIArtifact(ctx context.Context, _ ed25519.PublicKey) (msi.ArtifactRecord, error) {
	if e := msi.CheckFinal(ctx); e != nil {
		return msi.ArtifactRecord{}, e
	}
	raw, _ := json.Marshal(s.artifact)
	return msi.DecodeArtifactRecord(raw)
}
func (s *fleetMemoryStore) WindowsManagedMSIFleetBindings(context.Context, ed25519.PublicKey) ([]msi.Binding, error) {
	var out []msi.Binding
	for _, m := range s.members {
		out = append(out, m.r.Grant.Binding)
	}
	return out, nil
}
func (s *fleetMemoryStore) WindowsManagedMSIArtifactTransaction(ctx context.Context, k ed25519.PublicKey, at time.Time, fn func(*msi.ArtifactRecord, time.Time) error) (msi.ArtifactRecord, error) {
	r, e := s.ReadWindowsManagedMSIArtifact(ctx, k)
	if e != nil {
		return r, e
	}
	r.ClockFloor = *s.now
	if e = fn(&r, time.Unix(*s.now, 0)); e != nil {
		return r, e
	}
	if e = msi.CheckFinal(ctx); e != nil {
		return r, e
	}
	if r.Validate() != nil || msi.ArtifactRecordTransition(s.artifact, r) != nil {
		return r, msi.ErrIntegrity
	}
	s.artifact = r
	return r, nil
}

// Deterministic cancellation during the initial whole-file hash. No sleep or
// native installer is needed; a real protected spool holds synthetic bytes only.
type hashCancelContext struct {
	context.Context
	checks int
}

func (c *hashCancelContext) Err() error {
	c.checks++
	if c.checks >= 3 {
		return context.Canceled
	}
	return nil
}
func TestManagedFleetOneUploadIndependentTransfersAndCustody(t *testing.T) {
	dir, spool := protectedSpoolFixture(t)
	a, sa, _, actor, now := managerFixture(t)
	ctx := context.Background()
	b := Manager{store: a.store, binding: a.binding, key: bytes.Clone(a.key), spool: a.spool, now: a.now, configurationCheck: a.configurationCheck, deliveryAllowed: a.deliveryAllowed, installAllowed: a.installAllowed}
	b.binding.DeviceID = "agent_88888888888888888888888888888888"
	b.binding.ExecutorID = "executor_99999999999999999999999999999999"
	b.binding.DeliveryGrantID = "grant_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	b.binding.InstallGrantID = "grant_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	executor := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, 32))
	b.binding.ExecutorKeyID = msi.Digest(executor.Public().(ed25519.PublicKey))
	grant := sa.r.Grant
	grant.Binding = b.binding
	rb, e := msi.NewRecord(grant, sa.r.PublicKey, executor.Public().(ed25519.PublicKey), *now)
	if e != nil {
		t.Fatal(e)
	}
	current := sa.current
	current.Binding = b.binding
	sb := &memoryStore{r: rb, current: current, now: now}
	store := &fleetMemoryStore{members: map[string]*memoryStore{a.binding.DeviceID: sa, b.binding.DeviceID: sb}, artifact: msi.ArtifactRecord{Version: msi.ArtifactRecordVersion, ClockFloor: *now}, now: now}
	artifact, e := newArtifactManager(ctx, store, sa.r.PublicKey, spool, a.now, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	artifact.deliveryAllowed = func(id string) bool { return id == actor }
	a.store = store
	b.store = store
	a.spool = spool
	b.spool = spool
	a.artifact = artifact
	b.artifact = artifact
	registry, e := NewRegistry([]*Manager{a, &b})
	if e != nil {
		t.Fatal(e)
	}
	empty, e := a.View(ctx)
	if e != nil || empty.ArtifactID == nil || *empty.ArtifactID != "" || empty.BindingDigest == "" {
		t.Fatal("empty fleet reference pair", e)
	}
	wire, _ := json.Marshal(empty)
	var shape map[string]any
	if json.Unmarshal(wire, &shape) != nil || shape["artifactId"] != "" {
		t.Fatal("empty artifactId omitted")
	}
	raw := make([]byte, 2*msi.MaxChunkBytes)
	copy(raw, inertArtifact())
	sel := managerSelection()
	sel.Size = int64(len(raw))
	sel.SHA256 = msi.Digest(raw)
	native := msi.Digest([]byte("one exact native review"))
	if e = artifact.ReserveUpload(ctx, "", sel, native); !errors.Is(e, msi.ErrAuthority) {
		t.Fatal("unnamed reserve", e)
	}
	if e = artifact.ReserveUpload(ctx, actor, sel, native); e != nil {
		t.Fatal(e)
	}
	for i := uint32(0); i < 2; i++ {
		data := raw[int(i)*msi.MaxChunkBytes : int(i+1)*msi.MaxChunkBytes]
		if e = artifact.Upload(ctx, actor, UploadChunk{sel.SHA256, i, msi.Digest(data), data}); e != nil {
			t.Fatal(e)
		}
	}
	if e = artifact.CompleteUpload(ctx, actor); e != nil {
		t.Fatal(e)
	}
	files, e := os.ReadDir(SpoolPath(dir))
	if e != nil || len(files) != 1 || files[0].Name() != artifactName {
		t.Fatal("more than one artifact", e)
	}
	if sa.r.Artifact != nil || sb.r.Artifact != nil {
		t.Fatal("upload granted an endpoint")
	}
	view, e := registry.ArtifactView(ctx)
	if e != nil || view.State != "uploaded" || len(view.Targets) != 2 {
		t.Fatal(e)
	}
	av, e := a.View(ctx)
	if e != nil || av.State != "uploaded" || av.ArtifactID == nil || *av.ArtifactID != view.ArtifactID {
		t.Fatal(e)
	}
	aid, bid := "transfer_cccccccccccccccccccccccccccccccc", "transfer_dddddddddddddddddddddddddddddddd"
	if e = a.DeliverArtifact(ctx, actor, aid, true, view.ArtifactID, msi.BindingDigest(b.binding)); !errors.Is(e, msi.ErrConflict) {
		t.Fatal("cross-binding delivery", e)
	}
	if e = a.DeliverArtifact(ctx, actor, aid, true, view.ArtifactID, msi.BindingDigest(a.binding)); e != nil {
		t.Fatal(e)
	}
	if sb.r.Artifact != nil || sb.r.TransferID != "" {
		t.Fatal("A changed B")
	}
	if e = b.DeliverArtifact(ctx, actor, bid, true, view.ArtifactID, msi.BindingDigest(b.binding)); e != nil {
		t.Fatal(e)
	}
	pa, e := a.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	pb, e := b.Poll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(pa.Permit, pb.Permit) || sa.r.TransferID == sb.r.TransferID || *sa.r.Artifact != *sb.r.Artifact {
		t.Fatal("wrong independent transfers")
	}
	qa := msi.ChunkRequest{TransferID: aid, PermitDigest: msi.Digest(pa.Permit), Index: 0}
	qb := msi.ChunkRequest{TransferID: bid, PermitDigest: msi.Digest(pb.Permit), Index: 0}
	if _, e = b.Chunk(ctx, qa); e == nil {
		t.Fatal("cross-target chunk")
	}
	spool.cache = nil
	if _, e = a.Chunk(&hashCancelContext{Context: ctx}, qa); !errors.Is(e, context.Canceled) || spool.failed {
		t.Fatal("canceled A poisoned global custody", e)
	}
	if c, e := b.Chunk(ctx, qb); e != nil || !bytes.Equal(c.Data, raw[:msi.MaxChunkBytes]) {
		t.Fatal("B failed after A cancellation", e)
	}
	// Current per-device authority is checked again after the shared spool wait.
	calls := 0
	a.configurationCheck = func() error {
		calls++
		if calls >= 3 {
			return msi.ErrAuthority
		}
		return nil
	}
	if _, e = a.Chunk(ctx, qa); !errors.Is(e, msi.ErrAuthority) || spool.failed {
		t.Fatal("late A authority affected custody", e)
	}
	if _, e = b.Chunk(ctx, qb); e != nil {
		t.Fatal("A authority poisoned B", e)
	}
	a.configurationCheck = func() error { return nil }
	raw[500] = 1
	if e = os.WriteFile(filepath.Join(SpoolPath(dir), artifactName), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Chunk(ctx, qa); e == nil {
		t.Fatal("changed shared bytes released to A")
	}
	if _, e = b.Chunk(ctx, qb); e == nil {
		t.Fatal("changed shared bytes released to B")
	}
}
