package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	msi "localrmm/internal/windowsmanagedmsi"
	"strings"
	"testing"
)

func completeReusableOccurrence(t *testing.T, m *Manager, key ed25519.PrivateKey, actor, artifact, transfer string, now int64) {
	t.Helper()
	ctx := context.Background()
	if err := m.DeliverArtifact(ctx, actor, transfer, true, artifact, msi.BindingDigest(m.binding)); err != nil {
		t.Fatal("deliver", err)
	}
	poll, err := m.Poll(ctx)
	if err != nil {
		t.Fatal("poll delivery", err)
	}
	delivery := poll.Permit
	reusableManagerReport(t, m, key, delivery, "delivery", now)
	if err = m.Review(ctx, actor, true, true, true, true); err != nil {
		t.Fatal("review", err)
	}
	poll, err = m.Poll(ctx)
	if err != nil {
		t.Fatal("poll readiness", err)
	}
	ready := reusableManagerReport(t, m, key, poll.Permit, "readiness", now)
	reusableManagerReport(t, m, key, delivery, "mutation", now)
	if err = m.Approve(ctx, actor, msi.Digest(ready), true); err != nil {
		t.Fatal("approve", err)
	}
	poll, err = m.Poll(ctx)
	if err != nil {
		t.Fatal("poll install", err)
	}
	result := reusableManagerReport(t, m, key, poll.Permit, "result", now)
	if err = m.Retire(ctx, actor, msi.Digest(result), true); err != nil {
		t.Fatal("retire", err)
	}
	poll, err = m.Poll(ctx)
	if err != nil {
		t.Fatal("poll retire", err)
	}
	reusableManagerReport(t, m, key, poll.Permit, "retired", now)
}

func TestReusableRepeatedArtifactProjectsFreshOccurrenceAcrossSkippedPackage(t *testing.T) {
	m, store, key, actor, now, _ := reusableManagerFixture(t)
	defer m.Close()
	y := addReusableManagerTarget(t, m, store)
	defer y.Close()
	yKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	ctx := context.Background()
	first := reusableManagerUpload(t, m, actor, 'A')
	completeReusableOccurrence(t, m, key, actor, first, "transfer_"+strings.Repeat("1", 32), *now)
	if err := m.artifact.RetireArtifact(ctx, actor, first, true); err != nil {
		t.Fatal("retire first artifact", err)
	}
	*now++
	middle := reusableManagerUpload(t, m, actor, 'B')
	completeReusableOccurrence(t, y, yKey, actor, middle, "transfer_"+strings.Repeat("2", 32), *now)
	if err := m.artifact.RetireArtifact(ctx, actor, middle, true); err != nil {
		t.Fatal("retire middle artifact", err)
	}
	*now++
	last := reusableManagerUpload(t, m, actor, 'A')
	if last != first {
		t.Fatal("fixture did not repeat content identity")
	}
	before, _ := json.Marshal(store.members[m.binding.DeviceID].r)
	view, err := m.View(ctx)
	if err != nil || view.State != "uploaded" || view.TransferID != "" || view.JobSequence != "2" || view.RetiredFloor != "1" || len(view.History) != 1 || view.Result != nil {
		t.Fatalf("fresh repeated A projected old retired job: state=%s transfer=%s job=%s floor=%s history=%d err=%v", view.State, view.TransferID, view.JobSequence, view.RetiredFloor, len(view.History), err)
	}
	after, _ := json.Marshal(store.members[m.binding.DeviceID].r)
	// View may only advance its ordinary clock floor; it must never consume a job.
	var old, current msi.Record
	json.Unmarshal(before, &old)
	json.Unmarshal(after, &current)
	old.ClockFloor = current.ClockFloor
	oldRaw, _ := json.Marshal(old)
	if !bytes.Equal(oldRaw, after) {
		t.Fatal("view advanced durable job")
	}
}

func TestReusableOccurrencePinsRejectStaleMutationsAndKeepUnresolvedCustody(t *testing.T) {
	m, store, key, actor, now, _ := reusableManagerFixture(t)
	defer m.Close()
	ctx := context.Background()
	first := reusableManagerUpload(t, m, actor, 'A')
	oldTransfer := "transfer_" + strings.Repeat("1", 32)
	completeReusableOccurrence(t, m, key, actor, first, oldTransfer, *now)
	if err := m.artifact.RetireArtifact(ctx, actor, first, true); err != nil {
		t.Fatal(err)
	}
	*now++
	same := reusableManagerUpload(t, m, actor, 'A')
	if same != first {
		t.Fatal("not same-content fixture")
	}
	stale, err := WithArtifactRetiredCount(ctx, "0")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(store.artifact)
	for name, action := range map[string]func() error{
		"retire":   func() error { return m.artifact.RetireArtifact(stale, actor, same, true) },
		"complete": func() error { return m.artifact.CompleteUpload(stale, actor) },
		"reserve": func() error {
			a := store.artifact.Artifact
			return m.artifact.ReserveReusableUpload(stale, actor, a.Package, a.NativeAcceptanceDigest, a.PublisherStatus, a.PublisherEvidenceDigest)
		},
		"upload": func() error {
			a := store.artifact.Artifact
			data := inertArtifact()
			data[len(data)-1] = 'A'
			return m.artifact.Upload(stale, actor, UploadChunk{PackageDigest: a.Package.SHA256, Digest: msi.Digest(data), Data: data})
		},
		"deliver": func() error {
			return m.DeliverArtifact(stale, actor, "transfer_"+strings.Repeat("2", 32), true, same, msi.BindingDigest(m.binding))
		},
		"reference": func() error { return m.CheckArtifactReference(stale, same, msi.BindingDigest(m.binding)) },
	} {
		if err := action(); err != msi.ErrConflict {
			t.Fatalf("stale %s: %v", name, err)
		}
	}
	after, _ := json.Marshal(store.artifact)
	if !bytes.Equal(before, after) {
		t.Fatal("stale request changed artifact")
	}
	registry, err := NewRegistry([]*Manager{m})
	if err != nil {
		t.Fatal(err)
	}
	global, err := registry.ArtifactView(ctx)
	if err != nil || global.CanRetire == nil || !*global.CanRetire {
		t.Fatal("old retired report blocked unassigned occurrence", err)
	}
	current, err := WithArtifactRetiredCount(ctx, "1")
	if err != nil {
		t.Fatal(err)
	}
	transfer := "transfer_" + strings.Repeat("2", 32)
	if err = m.DeliverArtifact(current, actor, transfer, true, same, msi.BindingDigest(m.binding)); err != nil {
		t.Fatal(err)
	}
	r := store.members[m.binding.DeviceID].r
	if r.ArtifactRetiredCount != 1 || r.Jobs.Sequence != 2 || r.Jobs.RetiredFloor != 1 {
		t.Fatal("occurrence or signed job floor lost")
	}
	raw, _ := msi.EncodeRecord(r)
	decoded, err := msi.DecodeRecord(raw)
	if err != nil || decoded.ArtifactRetiredCount != 1 {
		t.Fatal("occurrence lost on restart decoding", err)
	}
	for _, floor := range []uint64{0, 2} {
		changed := decoded
		changed.ArtifactRetiredCount = floor
		if msi.Transition(decoded, changed) == nil {
			t.Fatal("same job changed occurrence floor")
		}
	}
	poll, err := m.Poll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reusableManagerReport(t, m, key, poll.Permit, "delivery", *now)
	for name, pin := range map[string][3]string{
		"old occurrence": {"0", transfer, "2"},
		"old transfer":   {"1", oldTransfer, "2"},
		"old sequence":   {"1", transfer, "1"},
	} {
		guarded, err := WithJobOccurrence(ctx, pin[0], pin[1], pin[2])
		if err != nil {
			t.Fatal(err)
		}
		if err = m.Review(guarded, actor, true, true, true, true); err != msi.ErrConflict {
			t.Fatalf("stale %s admitted review: %v", name, err)
		}
	}
	exact, err := WithJobOccurrence(ctx, "1", transfer, "2")
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Review(exact, actor, true, true, true, true); err != nil {
		t.Fatal("exact occurrence review", err)
	}
	global, err = registry.ArtifactView(ctx)
	if err != nil || global.CanRetire == nil || *global.CanRetire {
		t.Fatal("unresolved assigned occurrence shown retireable", err)
	}
	if err = m.artifact.RetireArtifact(current, actor, same, true); err != msi.ErrUncertain {
		t.Fatal("unresolved fresh payload retired", err)
	}
	if store.artifact.RetirementStarted || store.artifact.Retired {
		t.Fatal("failed retirement consumed fresh custody")
	}
}

func TestReusableOccurrencePinCanonicalNumbersAndLegacyBytes(t *testing.T) {
	ctx := context.Background()
	for _, value := range []string{"", "00", "01", "-1", "+1", " 1", "1 ", "18446744073709551616"} {
		if _, err := WithArtifactRetiredCount(ctx, value); err == nil {
			t.Fatalf("noncanonical occurrence %q", value)
		}
	}
	for _, value := range []string{"0", "1", "18446744073709551615"} {
		if _, err := WithArtifactRetiredCount(ctx, value); err != nil {
			t.Fatalf("valid occurrence %q: %v", value, err)
		}
	}
	legacy, s, _, _, _ := managerFixture(t)
	defer legacy.Close()
	raw, _ := msi.EncodeRecord(s.r)
	if bytes.Contains(raw, []byte("artifactRetiredCount")) {
		t.Fatal("legacy bytes gained occurrence")
	}
	s.r.ArtifactRetiredCount = 1
	if s.r.Validate() == nil {
		t.Fatal("legacy record adopted occurrence field")
	}
}

func TestReusableReservePinsInitialEmptyAndRetiredOccurrences(t *testing.T) {
	m, store, key, actor, now, _ := reusableManagerFixture(t)
	defer m.Close()
	ctx := context.Background()
	initial, err := WithArtifactReserveOccurrence(ctx, "0", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = checkArtifactOccurrence(initial, store.artifact); err != nil {
		t.Fatal("initial empty refused", err)
	}
	art := reusableManagerUpload(t, m, actor, 'A')
	completeReusableOccurrence(t, m, key, actor, art, "transfer_"+strings.Repeat("1", 32), *now)
	before, _ := json.Marshal(store.members[m.binding.DeviceID].r)
	for _, id := range []string{"transfer_" + strings.Repeat("1", 32), "transfer_" + strings.Repeat("2", 32)} {
		if err = m.DeliverArtifact(ctx, actor, id, true, art, msi.BindingDigest(m.binding)); err != msi.ErrConsumed {
			t.Fatal("retired same occurrence redelivered", err)
		}
	}
	after, _ := json.Marshal(store.members[m.binding.DeviceID].r)
	if !bytes.Equal(before, after) {
		t.Fatal("same occurrence attempt advanced ledger")
	}
	if err = m.artifact.RetireArtifact(ctx, actor, art, true); err != nil {
		t.Fatal(err)
	}
	saved := *store.artifact.Artifact
	if err = m.artifact.ReserveReusableUpload(initial, actor, saved.Package, saved.NativeAcceptanceDigest, saved.PublisherStatus, saved.PublisherEvidenceDigest); err != msi.ErrConflict {
		t.Fatal("late initial-empty request reused retired first floor", err)
	}
	exact, err := WithArtifactReserveOccurrence(ctx, "0", art)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.artifact.ReserveReusableUpload(exact, actor, saved.Package, saved.NativeAcceptanceDigest, saved.PublisherStatus, saved.PublisherEvidenceDigest); err != nil {
		t.Fatal("reviewed retired occurrence reserve", err)
	}
	if store.artifact.RetiredCount != 1 || store.artifact.Retired || store.artifact.Artifact.CompletedAt != 0 {
		t.Fatal("reserve floor/phase mismatch")
	}
	if err = m.artifact.ReserveReusableUpload(exact, actor, saved.Package, saved.NativeAcceptanceDigest, saved.PublisherStatus, saved.PublisherEvidenceDigest); err != msi.ErrConflict {
		t.Fatal("stale retired reserve repeated", err)
	}
}

func TestReusableViewRejectsUnresolvedOlderOccurrence(t *testing.T) {
	m, store, key, actor, now, _ := reusableManagerFixture(t)
	defer m.Close()
	ctx := context.Background()
	art := reusableManagerUpload(t, m, actor, 'A')
	completeReusableOccurrence(t, m, key, actor, art, "transfer_"+strings.Repeat("1", 32), *now)
	if err := m.artifact.RetireArtifact(ctx, actor, art, true); err != nil {
		t.Fatal(err)
	}
	*now++
	reusableManagerUpload(t, m, actor, 'B')
	// SQLite rejects this cross-record inconsistency during admission. Model a
	// store that validates records independently: View must still never label A's
	// unresolved result with B's current artifact identity and occurrence floor.
	saved := store.members[m.binding.DeviceID]
	saved.r.RetiredReport = nil
	if err := saved.r.Validate(); err != nil {
		t.Fatal("invalid per-record fixture", err)
	}
	before, _ := json.Marshal(saved.r)
	view, err := m.View(ctx)
	if err != msi.ErrUncertain || view.State != "" || view.ArtifactID != nil || view.Result != nil {
		t.Fatal("mixed unresolved occurrence projected", view, err)
	}
	after, _ := json.Marshal(saved.r)
	if !bytes.Equal(before, after) {
		t.Fatal("refused projection changed saved evidence")
	}
}
