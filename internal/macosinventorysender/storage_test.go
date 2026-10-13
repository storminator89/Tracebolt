package macosinventorysender

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	state "localrmm/internal/macosinventorystate"
	wire "localrmm/internal/macosinventorywire"
)

// Synthetic protocol model only: no disk, ACL, lock, fsync or Darwin claim.
type storageFake struct {
	files   map[string][]byte
	events  []string
	calls   int
	failAt  int
	after   bool
	panicAt bool
	closed  bool
}

func (b *storageFake) fault() error {
	if b.calls != b.failAt {
		return nil
	}
	if b.panicAt {
		panic("private storage callback panic")
	}
	return errors.New("private storage callback failure")
}
func (b *storageFake) snapshot() (map[string][]byte, error) {
	b.calls++
	b.events = append(b.events, "snapshot")
	if err := b.fault(); err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(b.files))
	for k, v := range b.files {
		out[k] = bytes.Clone(v)
	}
	return out, nil
}
func (b *storageFake) publish(name string, expected, next []byte) error {
	b.calls++
	b.events = append(b.events, name)
	if !b.after {
		if err := b.fault(); err != nil {
			return err
		}
	}
	if !bytes.Equal(b.files[name], expected) {
		return errors.New("fake expected bytes")
	}
	b.files[name] = bytes.Clone(next)
	if b.after {
		return b.fault()
	}
	return nil
}
func (b *storageFake) close() error { b.closed = true; return nil }
func storageFixtureEnable(t *testing.T) ([]byte, time.Time) {
	t.Helper()
	at := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	raw, err := wire.EncodeControl(wire.Control{SchemaVersion: wire.ControlVersion, Binding: wire.Binding{Platform: wire.Platform, Profile: wire.Profile, DeviceID: "agent_" + strings.Repeat("a", 32), SenderBinding: strings.Repeat("b", 64)}, GrantID: strings.Repeat("c", 32), GrantRevision: 1, ControlRevision: 1, Enabled: true, ChangedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	return raw, at
}
func storageFixtureCheckpoint(t *testing.T, enable []byte, at time.Time) []byte {
	t.Helper()
	c := &storageInitialCapture{}
	p, err := state.InitializeFresh(c, enable, at)
	if err != nil {
		t.Fatal(err)
	}
	p.Close()
	return bytes.Clone(c.raw)
}
func storageFixture(t *testing.T) (*Storage, *storageFake, []byte, []byte, time.Time) {
	t.Helper()
	enable, at := storageFixtureEnable(t)
	b := &storageFake{files: make(map[string][]byte)}
	s, _, err := openStorageProtocol(b, enable, true)
	if err != nil {
		t.Fatal(err)
	}
	raw := storageFixtureCheckpoint(t, enable, at)
	return s, b, enable, raw, at
}
func storageRecover(f func()) (panicked bool) {
	defer func() {
		if recover() != nil {
			panicked = true
		}
	}()
	f()
	return false
}

func TestStorageIrreversibleFreshPublicationOrder(t *testing.T) {
	s, b, enable, raw, _ := storageFixture(t)
	if s.CreateFresh(raw) != nil {
		t.Fatal("fresh rejected")
	}
	want := []string{"snapshot", "snapshot", storageUsedName, storageCheckpointName, storageReadyName, "snapshot"}
	if fmt.Sprint(b.events) != fmt.Sprint(want) {
		t.Fatalf("wrong publication order: %v", b.events)
	}
	if !bytes.Equal(b.files[storageUsedName], storageMarker(storageUsedName, enable)) || !bytes.Equal(b.files[storageReadyName], storageMarker(storageReadyName, enable)) {
		t.Fatal("exact original binding missing")
	}
	if s.CreateFresh(raw) == nil {
		t.Fatal("reinitialization accepted")
	}
	if s.Commit(raw, raw) != nil {
		t.Fatal("verified no-op rejected")
	}
	if err := s.Close(); err != nil || !b.closed {
		t.Fatal("ownership not released")
	}
	if s.Commit(raw, raw) == nil || s.CreateFresh(raw) == nil {
		t.Fatal("closed owner reused")
	}
}
func TestStorageFreshFaultsNeverResumeOrReset(t *testing.T) {
	// Calls after open: verify; used; checkpoint; ready; final verify. A fault
	// before or after any publication must poison, including recovered panics.
	for step := 2; step <= 6; step++ {
		for _, after := range []bool{false, true} {
			for _, panics := range []bool{false, true} {
				t.Run(fmt.Sprintf("step%d_after%t_panic%t", step, after, panics), func(t *testing.T) {
					s, b, enable, raw, _ := storageFixture(t)
					b.failAt, b.after, b.panicAt = step, after, panics
					var err error
					panicSeen := storageRecover(func() { err = s.CreateFresh(raw) })
					if !panicSeen && err == nil {
						t.Fatal("uncertain create succeeded")
					}
					b.failAt = 0
					calls := b.calls
					if s.CreateFresh(raw) == nil || s.Commit(raw, raw) == nil || b.calls != calls {
						t.Fatal("poisoned callback reused")
					}
					// Any surviving fence/checkpoint blocks fresh protocol open. A backend
					// lock alone also blocks fresh on Darwin, beyond this file-only model.
					if len(b.files) > 0 {
						if other, _, err := openStorageProtocol(b, enable, true); err == nil {
							other.Close()
							t.Fatal("interrupted files adopted fresh")
						}
					}
					if len(b.files) > 0 && len(b.files) < 3 {
						if other, _, err := openStorageProtocol(b, enable, false); err == nil {
							other.Close()
							t.Fatal("partial initialization resumed")
						}
					}
				})
			}
		}
	}
}
func TestStorageMissingMarkersCheckpointAndForeignBinding(t *testing.T) {
	for _, missing := range []string{storageUsedName, storageReadyName, storageCheckpointName} {
		t.Run(missing, func(t *testing.T) {
			s, b, enable, raw, _ := storageFixture(t)
			if s.CreateFresh(raw) != nil {
				t.Fatal("create")
			}
			delete(b.files, missing)
			if s.Commit(raw, raw) == nil {
				t.Fatal("missing state accepted by no-op")
			}
			if _, _, err := openStorageProtocol(b, enable, false); err == nil {
				t.Fatal("missing state reopened")
			}
			if _, _, err := openStorageProtocol(b, enable, true); err == nil {
				t.Fatal("missing state reset")
			}
		})
	}
	s, b, enable, raw, _ := storageFixture(t)
	if s.CreateFresh(raw) != nil {
		t.Fatal("create")
	}
	other := bytes.Replace(enable, []byte(strings.Repeat("c", 32)), []byte(strings.Repeat("d", 32)), 1)
	if _, _, err := openStorageProtocol(b, other, false); err == nil {
		t.Fatal("foreign original adopted")
	}
	for _, name := range []string{storageUsedName, storageReadyName} {
		original := b.files[name]
		b.files[name] = append(bytes.Clone(original), '\n')
		if _, _, err := openStorageProtocol(b, enable, false); err == nil {
			t.Fatal("noncanonical marker adopted")
		}
		b.files[name] = original
	}
}
func TestStorageUnknownAndInterruptedFilesFailClosed(t *testing.T) {
	for _, name := range []string{storageTempName, "unknown", "old-checkpoint.json"} {
		s, b, enable, raw, _ := storageFixture(t)
		if s.CreateFresh(raw) != nil {
			t.Fatal("create")
		}
		b.files[name] = []byte("retained interrupted bytes")
		if s.Commit(raw, raw) == nil {
			t.Fatal("unknown file ignored")
		}
		if _, _, err := openStorageProtocol(b, enable, false); err == nil {
			t.Fatal("unknown file repaired")
		}
		if string(b.files[name]) != "retained interrupted bytes" {
			t.Fatal("unknown file removed")
		}
	}
}
func TestStorageCommitUncertaintyExactReopenAndMarkerImmutability(t *testing.T) {
	for step := 1; step <= 3; step++ {
		for _, after := range []bool{false, true} {
			for _, panics := range []bool{false, true} {
				s, b, enable, raw, at := storageFixture(t)
				if s.CreateFresh(raw) != nil {
					t.Fatal("create")
				}
				used, ready := bytes.Clone(b.files[storageUsedName]), bytes.Clone(b.files[storageReadyName])
				next := storageFixtureCheckpoint(t, enable, at.Add(time.Second))
				b.calls, b.failAt, b.after, b.panicAt = 0, step, after, panics
				var err error
				panicSeen := storageRecover(func() { err = s.Commit(raw, next) })
				if !panicSeen && err == nil {
					t.Fatal("uncertain commit succeeded")
				}
				b.failAt = 0
				calls := b.calls
				if s.Commit(raw, next) == nil || b.calls != calls {
					t.Fatal("uncertain owner retried")
				}
				if !bytes.Equal(used, b.files[storageUsedName]) || !bytes.Equal(ready, b.files[storageReadyName]) {
					t.Fatal("immutable markers rewritten")
				}
				restored, actual, err := openStorageProtocol(b, enable, false)
				if err != nil {
					t.Fatal("durable actual checkpoint not inspected")
				}
				want := raw
				if step > 2 || step == 2 && after {
					want = next
				}
				if !bytes.Equal(actual, want) {
					t.Fatal("reopen substituted old in-memory bytes")
				}
				if restored.Commit(actual, actual) != nil {
					t.Fatal("reopened exact no-op rejected")
				}
			}
		}
	}
}
func TestStorageCanonicalFreshAndExpectedGuards(t *testing.T) {
	s, b, enable, raw, at := storageFixture(t)
	if s.CreateFresh(raw) != nil {
		t.Fatal("create")
	}
	next := storageFixtureCheckpoint(t, enable, at.Add(time.Second))
	if s.Commit(next, raw) == nil {
		t.Fatal("stale expected accepted")
	}
	calls := b.calls
	if s.Commit(raw, next) == nil || b.calls != calls {
		t.Fatal("conflicting owner not poisoned")
	}
	// Fresh must not adopt a structurally valid already-acknowledged checkpoint.
	receipt, err := wire.ReceiptFor(enable, at)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := wire.EncodeReceipt(receipt, enable)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture")
	}
	ackJSON, _ := json.Marshal(ack)
	historical := bytes.Replace(raw, []byte(`"enableReceipt":null`), append([]byte(`"enableReceipt":`), ackJSON...), 1)
	if state.ValidateCheckpoint(historical, enable) != nil {
		t.Fatal("invalid historical fixture")
	}
	if storageFreshCheckpoint(historical, enable) {
		t.Fatal("historical checkpoint adopted")
	}
	for _, mutated := range [][]byte{nil, append(bytes.Clone(raw), '\n'), bytes.Replace(raw, []byte(`"used":true`), []byte(`"used":false`), 1)} {
		if storageFreshCheckpoint(mutated, enable) {
			t.Fatal("invalid fresh accepted")
		}
	}
}
func TestStorageCopiesAndRedaction(t *testing.T) {
	s, b, enable, raw, _ := storageFixture(t)
	if s.CreateFresh(raw) != nil {
		t.Fatal("create")
	}
	enable[0] = 'x'
	raw[0] = 'x'
	if !storageLayout(b.files, s.original, true) {
		t.Fatal("retained caller aliases")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(format, s); strings.Contains(got, "agent_") || strings.Contains(got, "original") {
			t.Fatal("format leaked state")
		}
	}
	encoded, err := json.Marshal(s)
	if err != nil || string(encoded) != `{"contentsRedacted":true}` {
		t.Fatal("JSON redaction")
	}
}
func TestStorageSerializesCallbacks(t *testing.T) {
	s, _, _, raw, _ := storageFixture(t)
	if s.CreateFresh(raw) != nil {
		t.Fatal("create")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Commit(raw, raw) != nil {
				t.Error("serialized no-op")
			}
		}()
	}
	wg.Wait()
}
