//go:build linux

package windowsmanagedmsimanager

import (
	"bytes"
	"context"
	msi "localrmm/internal/windowsmanagedmsi"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func protectedSpoolFixture(t *testing.T) (string, *Spool) {
	t.Helper()
	dir, e := os.MkdirTemp(".", ".managed-msi-source-fixture-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	absolute, e := filepath.Abs(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = CreateSpool(absolute); e != nil {
		t.Skip("protected-ancestor fixture unavailable", e)
	}
	s, e := OpenSpool(absolute)
	if e != nil {
		t.Fatal(e)
	}
	return absolute, s
}
func inertArtifact() []byte {
	raw := make([]byte, 1024)
	copy(raw, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	return raw
}
func pendingArtifact(raw []byte) msi.Artifact {
	sel := managerSelection()
	sel.SHA256 = byteDigest(raw)
	sel.Size = int64(len(raw))
	return msi.Artifact{Package: sel, NativeAcceptanceDigest: msi.Digest([]byte("inert native fixture")), IntentAt: 1800000000, PrefixDigest: msi.Digest(nil), PendingDigest: msi.Digest(raw), PendingSize: len(raw)}
}
func TestSpoolSingleLinkExactChunksAndSameByteRecovery(t *testing.T) {
	dir, s := protectedSpoolFixture(t)
	raw := inertArtifact()
	a := pendingArtifact(raw)
	ctx := context.Background()
	check := func() error { return nil }
	prefix, e := s.Append(ctx, a, raw, check)
	if e != nil || prefix != a.Package.SHA256 {
		t.Fatal(e)
	}
	reopened, e := OpenSpool(dir)
	if e != nil {
		t.Fatal(e)
	}
	prefix, e = reopened.Append(ctx, a, raw, check)
	if e != nil || prefix != a.Package.SHA256 {
		t.Fatal("exact unacknowledged tail recovery", e)
	}
	chunk, e := reopened.ReadChunk(ctx, a.Package, 0, check)
	if e != nil || !bytes.Equal(chunk, raw) {
		t.Fatal(e)
	}
	if e = os.Link(filepath.Join(SpoolPath(dir), artifactName), filepath.Join(dir, "extra-link")); e != nil {
		t.Fatal(e)
	}
	if _, e = reopened.ReadChunk(ctx, a.Package, 0, check); e == nil {
		t.Fatal("hardlink released")
	}
}
func TestSpoolChangedUnacknowledgedTailIsNeverOverwritten(t *testing.T) {
	dir, s := protectedSpoolFixture(t)
	raw := inertArtifact()
	a := pendingArtifact(raw)
	ctx := context.Background()
	if _, e := s.Append(ctx, a, raw, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(SpoolPath(dir), artifactName)
	changed := bytes.Clone(raw)
	changed[500] = 1
	if e := os.WriteFile(path, changed, 0600); e != nil {
		t.Fatal(e)
	}
	s, e := OpenSpool(dir)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Append(ctx, a, raw, func() error { return nil }); e == nil {
		t.Fatal("changed tail adopted")
	}
	saved, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(saved, changed) {
		t.Fatal("changed tail overwritten", e)
	}
}

func TestManagedUploadCheckpointAndCompletionUncertaintyRetainSameBytes(t *testing.T) {
	dir, spool := protectedSpoolFixture(t)
	m, s, _, actor, n := managerFixture(t)
	m.spool = spool
	ctx := context.Background()
	raw := inertArtifact()
	a := pendingArtifact(raw)
	if e := m.ReserveUpload(ctx, actor, a.Package, a.NativeAcceptanceDigest); e != nil {
		t.Fatal(e)
	}
	q := UploadChunk{PackageDigest: a.Package.SHA256, Index: 0, Digest: msi.Digest(raw), Data: raw}
	s.failCall = s.calls + 4
	if e := m.Upload(ctx, actor, q); e != msi.ErrUncertain {
		t.Fatal("expected metadata checkpoint uncertainty", e)
	}
	if s.r.Artifact.Offset != 0 || s.r.Artifact.PendingDigest != q.Digest {
		t.Fatal("lost pending chunk evidence")
	}
	if _, e := m.View(ctx); e != msi.ErrUncertain {
		t.Fatal("continued poisoned manager", e)
	}
	s.failCall = 0
	reopen := func() *Manager {
		sp, e := OpenSpool(dir)
		if e != nil {
			t.Fatal(e)
		}
		return &Manager{store: s, binding: m.binding, key: bytes.Clone(m.key), spool: sp, now: func() time.Time { return time.Unix(*n, 0) }, configurationCheck: func() error { return nil }, deliveryAllowed: func(string) bool { return true }, installAllowed: func(string) bool { return true }}
	}
	m = reopen()
	if e := m.Upload(ctx, actor, q); e != nil {
		t.Fatal("same pending bytes recovery", e)
	}
	if s.r.Artifact.Offset != int64(len(raw)) || s.r.Artifact.PendingDigest != "" {
		t.Fatal("chunk not checkpointed")
	}
	s.failCall = s.calls + 4
	if e := m.CompleteUpload(ctx, actor); e != msi.ErrUncertain {
		t.Fatal("completion uncertainty", e)
	}
	if s.r.Artifact.CompletedAt != 0 {
		t.Fatal("failed completion invented receipt")
	}
	s.failCall = 0
	m = reopen()
	if e := m.CompleteUpload(ctx, actor); e != nil {
		t.Fatal("exact completion reconciliation", e)
	}
	saved, e := os.ReadFile(filepath.Join(SpoolPath(dir), artifactName))
	if e != nil || !bytes.Equal(saved, raw) || s.r.Artifact.CompletedAt != *n {
		t.Fatal("changed bytes or timestamp", e)
	}
}
