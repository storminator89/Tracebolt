package windowspackage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"localrmm/internal/windowsservice"
)

// In-memory filesystem only. No host file, service, ACL or update API is used.
type updateImageFixture struct {
	file          []byte
	id            uint32
	links         int
	protected     bool
	defaultStream bool
	ownedStopped  bool
	creates       int
	deletes       int
	closes        int
	createFail    bool
	deleteFail    bool
	checkFail     bool
	checkHook     func()
	deleteHook    func()
	closeError    error
}

func newUpdateImageFixture() *updateImageFixture {
	return &updateImageFixture{id: 31, links: 1, protected: true, defaultStream: true, ownedStopped: true}
}
func (f *updateImageFixture) Path() string {
	return `C:\Program Files\Tracebolt\` + UpdateExecutorImageName
}
func (f *updateImageFixture) Check(ctx context.Context) error {
	if f.checkHook != nil {
		f.checkHook()
	}
	if cancelled(ctx) || f.checkFail || !f.ownedStopped {
		return failure("fixture-binding")
	}
	return nil
}
func (f *updateImageFixture) CheckAbsent(context.Context) error {
	if f.file != nil {
		return failure("existing-resource")
	}
	return nil
}
func (f *updateImageFixture) Create(ctx context.Context, payload []byte) (UpdateExecutorImageReceipt, error) {
	f.creates++
	if f.file != nil {
		return UpdateExecutorImageReceipt{}, failure("existing-resource")
	}
	f.file = append([]byte(nil), payload...)
	if f.createFail {
		f.file = f.file[:200] // A failed write retains a partial, unowned image.
		return UpdateExecutorImageReceipt{}, failure("file-write")
	}
	return f.Read(ctx, false)
}
func (f *updateImageFixture) Read(_ context.Context, _ bool) (UpdateExecutorImageReceipt, error) {
	if f.file == nil || f.links != 1 || !f.defaultStream || !f.protected {
		return UpdateExecutorImageReceipt{}, failure("fixture-file-binding")
	}
	digest := sha256.Sum256(f.file)
	return UpdateExecutorImageReceipt{Version: UpdateExecutorImageVersion, Path: f.Path(), SHA256: "sha256:" + hex.EncodeToString(digest[:]), Size: int64(len(f.file)), VolumeSerialNumber: 9, FileIndexLow: f.id}, nil
}
func (f *updateImageFixture) Delete(ctx context.Context, original UpdateExecutorImageReceipt) error {
	if f.deleteHook != nil {
		f.deleteHook()
	}
	observed, err := f.Read(ctx, true)
	if err != nil || observed != original {
		return failure("image-identity")
	}
	f.deletes++
	if f.deleteFail {
		return failure("image-remove")
	}
	f.file = nil
	return nil
}
func (f *updateImageFixture) Close() error { f.closes++; return f.closeError }
func (f *updateImageFixture) open(ctx context.Context, _ windowsservice.Receipt) (updateImageBackend, error) {
	return f, nil
}
func fixtureUpdateImage(t *testing.T, f *updateImageFixture) UpdateExecutorImage {
	t.Helper()
	s, err := openUpdateExecutorImageWith(context.Background(), windowsservice.Receipt{}, "amd64", f.open)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func createFixtureUpdateImage(t *testing.T, s UpdateExecutorImage) UpdateExecutorImageReceipt {
	t.Helper()
	payload := fixturePE("amd64")
	r, err := s.Create(context.Background(), payload, fixtureManifest(payload, "amd64"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUpdateExecutorImageCreateVerifyOwnedRemove(t *testing.T) {
	f := newUpdateImageFixture()
	s := fixtureUpdateImage(t, f)
	ctx := context.Background()
	if err := s.CheckAbsent(ctx); err != nil {
		t.Fatal(err)
	}
	r := createFixtureUpdateImage(t, s)
	if r.Validate() != nil || f.creates != 1 || f.closes != 0 {
		t.Fatal("creation proof or pin lifetime", r, f)
	}
	if err := s.Verify(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAbsent(ctx); err == nil {
		t.Fatal("created image treated as absent")
	}
	if err := s.Remove(ctx, r); err != nil || f.deletes != 1 || f.file != nil {
		t.Fatal("owned removal failed", err)
	}
	if err := s.CheckAbsent(ctx); err != nil {
		t.Fatal("successful removal blocked read-only tombstone confirmation", err)
	}
	if err := s.Verify(ctx, r); err == nil {
		t.Fatal("removed image verified")
	}
	payload := fixturePE("amd64")
	if _, err := s.Create(ctx, payload, fixtureManifest(payload, "amd64")); err == nil || f.creates != 1 {
		t.Fatal("image recreated after removal")
	}
	if err := s.Remove(ctx, r); err == nil || f.deletes != 1 {
		t.Fatal("removal repeated")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil || f.closes != 1 {
		t.Fatal("close repeated", f.closes, err)
	}
}

func TestUpdateExecutorImageExistingPartialAndUnownedRejected(t *testing.T) {
	for _, partial := range []bool{false, true} {
		f := newUpdateImageFixture()
		f.file = fixturePE("amd64")
		if partial {
			f.file = f.file[:200]
		}
		s := fixtureUpdateImage(t, f)
		payload := fixturePE("amd64")
		if _, err := s.Create(context.Background(), payload, fixtureManifest(payload, "amd64")); err == nil || f.creates != 0 {
			t.Fatal("existing or partial object adopted")
		}
		if err := s.Remove(context.Background(), UpdateExecutorImageReceipt{}); err == nil || f.deletes != 0 {
			t.Fatal("image removed without original proof")
		}
	}
	f := newUpdateImageFixture()
	f.ownedStopped = false
	if _, err := openUpdateExecutorImageWith(context.Background(), windowsservice.Receipt{}, "amd64", f.open); err == nil || f.creates != 0 || f.deletes != 0 || f.closes != 1 {
		t.Fatal("unowned or running observer admitted")
	}
}

func TestUpdateExecutorImageChangedIdentityDigestLinkOrProtectionRejected(t *testing.T) {
	for name, change := range map[string]func(*updateImageFixture){
		"identity with identical bytes": func(f *updateImageFixture) { f.id++ },
		"digest":                        func(f *updateImageFixture) { f.file[700]++ },
		"partial":                       func(f *updateImageFixture) { f.file = f.file[:200] },
		"hardlink":                      func(f *updateImageFixture) { f.links = 2 },
		"additional stream":             func(f *updateImageFixture) { f.defaultStream = false },
		"ACL":                           func(f *updateImageFixture) { f.protected = false },
		"observer changed":              func(f *updateImageFixture) { f.ownedStopped = false },
	} {
		t.Run(name, func(t *testing.T) {
			f := newUpdateImageFixture()
			s := fixtureUpdateImage(t, f)
			r := createFixtureUpdateImage(t, s)
			change(f)
			if err := s.Verify(context.Background(), r); err == nil {
				t.Fatal("changed object verified")
			}
			if err := s.Remove(context.Background(), r); err == nil || f.deletes != 0 {
				t.Fatal("changed object removed")
			}
		})
	}
}

func TestUpdateExecutorImageMutationsFailClosedWithoutRetry(t *testing.T) {
	ctx := context.Background()
	f := newUpdateImageFixture()
	f.createFail = true
	s := fixtureUpdateImage(t, f)
	payload := fixturePE("amd64")
	m := fixtureManifest(payload, "amd64")
	r, err := s.Create(ctx, payload, m)
	if err == nil || r != (UpdateExecutorImageReceipt{}) || len(f.file) != 200 {
		t.Fatal("uncertain create supplied ownership or cleaned up")
	}
	f.createFail = false
	if _, err := s.Create(ctx, payload, m); err == nil || f.creates != 1 || f.deletes != 0 {
		t.Fatal("partial create retried or removed")
	}

	for _, changed := range []bool{false, true} {
		f := newUpdateImageFixture()
		s := fixtureUpdateImage(t, f)
		r := createFixtureUpdateImage(t, s)
		if changed {
			f.deleteHook = func() { f.id++ }
		} else {
			f.deleteFail = true
		}
		if err := s.Remove(ctx, r); err == nil || f.file == nil {
			t.Fatal("failed removal reported success")
		}
		attempts := f.deletes
		f.deleteFail, f.deleteHook = false, nil
		if err := s.Remove(ctx, r); err == nil || f.deletes != attempts {
			t.Fatal("uncertain removal retried")
		}
	}
}

func TestUpdateExecutorImageSnapshotAndManifestValidationBeforeMutation(t *testing.T) {
	f := newUpdateImageFixture()
	s := fixtureUpdateImage(t, f)
	payload := fixturePE("amd64")
	m := fixtureManifest(payload, "amd64")
	f.checkHook = func() { payload[700]++ }
	r, err := s.Create(context.Background(), payload, m)
	if err != nil || r.SHA256 != "sha256:"+m.SHA256 || m.Validate(f.file) != nil {
		t.Fatal("caller bytes changed verified creation", err)
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.SHA256 = strings.Repeat("a", 64) },
		func(m *Manifest) { m.Architecture = "arm64" },
	} {
		f := newUpdateImageFixture()
		s := fixtureUpdateImage(t, f)
		p := fixturePE("amd64")
		m := fixtureManifest(p, "amd64")
		mutate(&m)
		if _, err := s.Create(context.Background(), p, m); err == nil || f.creates != 0 {
			t.Fatal("bad manifest admitted")
		}
	}
}

func TestUpdateExecutorImageBadProofAndCancelledOrClosedSession(t *testing.T) {
	for _, mutate := range []func(*UpdateExecutorImageReceipt){
		func(r *UpdateExecutorImageReceipt) { r.Version = "" },
		func(r *UpdateExecutorImageReceipt) { r.Path = `D:\Program Files\Tracebolt\` + UpdateExecutorImageName },
		func(r *UpdateExecutorImageReceipt) { r.Path += ".other" },
		func(r *UpdateExecutorImageReceipt) { r.SHA256 = "sha256:" + strings.Repeat("A", 64) },
		func(r *UpdateExecutorImageReceipt) { r.Size = 0 },
		func(r *UpdateExecutorImageReceipt) { r.VolumeSerialNumber, r.FileIndexHigh, r.FileIndexLow = 0, 0, 0 },
	} {
		f := newUpdateImageFixture()
		s := fixtureUpdateImage(t, f)
		r := createFixtureUpdateImage(t, s)
		mutate(&r)
		if err := s.Remove(context.Background(), r); err == nil || f.deletes != 0 {
			t.Fatal("invalid or foreign receipt removed an image")
		}
	}
	f := newUpdateImageFixture()
	s := fixtureUpdateImage(t, f)
	r := createFixtureUpdateImage(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Remove(ctx, r); err == nil || f.deletes != 0 {
		t.Fatal("cancelled removal proceeded")
	}
	f.closeError = errors.New("injected close")
	if !errors.Is(s.Close(), f.closeError) || !errors.Is(s.Close(), f.closeError) || f.closes != 1 {
		t.Fatal("close result lost or repeated")
	}
	if err := s.Remove(context.Background(), r); err == nil || f.deletes != 0 {
		t.Fatal("closed session removal proceeded")
	}
}
