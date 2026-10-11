package lanclient

import (
	"bytes"
	"errors"
	"localrmm/internal/windowsstorageio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type storageIOConsentMemory struct {
	raw                         []byte
	writes                      int
	closed                      bool
	readErr, writeErr, closeErr error
}

func (s *storageIOConsentMemory) Read(name string) ([]byte, error) {
	if name != "consent.json" {
		return nil, ErrState
	}
	if s.readErr != nil {
		return nil, s.readErr
	}
	if s.raw == nil {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(s.raw), nil
}
func (s *storageIOConsentMemory) Write(name string, b []byte) error {
	if name != "consent.json" {
		return ErrState
	}
	s.writes++
	if s.writeErr != nil {
		return s.writeErr
	}
	s.raw = bytes.Clone(b)
	return nil
}
func (s *storageIOConsentMemory) Close() error { s.closed = true; return s.closeErr }
func TestWindowsStorageIOConsentCreateOnlyAndReenable(t *testing.T) {
	binding := strings.Repeat("a", 64)
	store := &storageIOConsentMemory{}
	exists := false
	opens, creates := 0, 0
	open := func(create bool) (storageIOConsentStore, error) {
		opens++
		if create {
			creates++
			if exists {
				return nil, ErrState
			}
			exists = true
		} else if !exists {
			return nil, os.ErrNotExist
		}
		store.closed = false
		return store, nil
	}
	r, e := updateWindowsStorageIOConsent(binding, "preview", open)
	if e != nil || r.Enabled || creates != 0 || store.writes != 0 {
		t.Fatal("preview wrote state", e)
	}
	r, e = updateWindowsStorageIOConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || store.writes != 1 || !store.closed {
		t.Fatal("fresh grant not committed", e)
	}
	first := bytes.Clone(store.raw)
	c, _ := windowsstorageio.DecodeConsent(first, binding)
	r, e = updateWindowsStorageIOConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || !bytes.Equal(first, store.raw) {
		t.Fatal("repeated enable replaced grant")
	}
	r, e = updateWindowsStorageIOConsent(binding, "disable", open)
	if e != nil || r.Enabled {
		t.Fatal("disable failed")
	}
	off, _ := windowsstorageio.DecodeConsent(store.raw, binding)
	if off.Enabled || off.GrantID != c.GrantID {
		t.Fatal("disable erased grant")
	}
	r, e = updateWindowsStorageIOConsent(binding, "enable", open)
	if e != nil || !r.Enabled {
		t.Fatal(e)
	}
	renewed, _ := windowsstorageio.DecodeConsent(store.raw, binding)
	if renewed.GrantID == c.GrantID || creates != 1 || opens < 5 {
		t.Fatal("reenable reused revoked grant")
	}
}
func TestWindowsStorageIOConsentRejectsIncompleteForeignAndFailedStorage(t *testing.T) {
	binding := strings.Repeat("a", 64)
	c := windowsstorageio.Consent{SchemaVersion: windowsstorageio.ConsentVersion, Scope: windowsstorageio.Scope, SenderBinding: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 32), Enabled: true}
	foreign, _ := windowsstorageio.EncodeConsent(c, c.SenderBinding)
	for name, store := range map[string]*storageIOConsentMemory{"incomplete": {}, "foreign": {raw: foreign}, "malformed": {raw: []byte(`{}`)}, "read-failure": {readErr: errors.New("fixture")}} {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(store.raw)
			creates := 0
			_, e := updateWindowsStorageIOConsent(binding, "enable", func(create bool) (storageIOConsentStore, error) {
				if create {
					creates++
				}
				return store, nil
			})
			if e == nil || creates != 0 || store.writes != 0 || !bytes.Equal(before, store.raw) {
				t.Fatal("existing state adopted or rewritten")
			}
		})
	}
	for _, failure := range []string{"write", "close"} {
		t.Run(failure, func(t *testing.T) {
			store := &storageIOConsentMemory{}
			if failure == "write" {
				store.writeErr = ErrState
			} else {
				store.closeErr = ErrState
			}
			_, e := updateWindowsStorageIOConsent(binding, "enable", func(create bool) (storageIOConsentStore, error) {
				if !create {
					return nil, os.ErrNotExist
				}
				return store, nil
			})
			if e == nil {
				t.Fatal("failed durable operation reported success")
			}
		})
	}
}

func TestWindowsStorageIOConsentNeverCreatesOnPreviewDisableOrAccessFailure(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, mode := range []string{"preview", "disable"} {
		r, err := updateWindowsStorageIOConsent(binding, mode, func(create bool) (storageIOConsentStore, error) {
			if create {
				t.Fatal("non-enable created state")
			}
			return nil, os.ErrNotExist
		})
		if err != nil || r.Enabled || r.Scope != windowsstorageio.Scope {
			t.Fatal("missing grant not default-off", err)
		}
	}
	for _, mode := range []string{"preview", "enable", "disable"} {
		_, err := updateWindowsStorageIOConsent(binding, mode, func(create bool) (storageIOConsentStore, error) {
			if create {
				t.Fatal("access error adopted as fresh")
			}
			return nil, os.ErrPermission
		})
		if err == nil {
			t.Fatal("access failure accepted")
		}
	}
	for _, acknowledged := range []bool{false, true} {
		mode := "enable"
		if acknowledged {
			mode = "disable"
		}
		if _, err := ConfigureWindowsStorageIO("never-opened", mode, acknowledged, false); err != ErrConfiguration {
			t.Fatal("invalid ack reached host", err)
		}
	}
}
func TestWindowsStorageIOConsentSeparateProtectedManifest(t *testing.T) {
	opts := windowsStorageIOOptions("fixture-sid", false)
	events := windowsEventOptions("fixture-sid", false)
	if opts.RuntimeSID != "fixture-sid" || opts.Create || opts.MaxBytes != 1024 || len(opts.Names) != 1 || opts.Names[0] != "consent.json" || opts.LockName == events.LockName || opts.TempName == events.TempName {
		t.Fatal("network state not separately bounded")
	}
}

func TestWindowsStorageIOConsentMissingExistingRecordFailsClosedEveryMode(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		store := &storageIOConsentMemory{}
		calls := 0
		_, err := updateWindowsStorageIOConsent(strings.Repeat("a", 64), mode, func(create bool) (storageIOConsentStore, error) {
			calls++
			if create {
				t.Fatal("missing record recreated")
			}
			return store, nil
		})
		if err == nil || calls != 1 || store.writes != 0 || !store.closed {
			t.Fatal(mode, "missing existing record accepted")
		}
	}
}

func TestWindowsStorageIOConsentFreshCreateRacesAndFailuresDoNotAdopt(t *testing.T) {
	for _, failure := range []error{os.ErrExist, os.ErrPermission, ErrState} {
		calls := 0
		_, err := updateWindowsStorageIOConsent(strings.Repeat("a", 64), "enable", func(create bool) (storageIOConsentStore, error) {
			calls++
			if !create {
				return nil, os.ErrNotExist
			}
			return nil, failure
		})
		if err == nil || calls != 2 {
			t.Fatal("failed create retried or adopted", calls, err)
		}
	}
	_, err := updateWindowsStorageIOConsent(strings.Repeat("a", 64), "enable", func(bool) (storageIOConsentStore, error) { return nil, nil })
	if err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestWindowsStorageIOConsentStorageIsolation(t *testing.T) {
	m := Material{config: Config{StateDirectory: filepath.Join("fixture", "state", "sender", "runtime")}}
	network := windowsStorageIOConsentDirectory(m)
	if network == windowsVolumeConsentDirectory(m) || network == windowsProcessMetricsConsentDirectory(m) || !strings.HasSuffix(network, "-storage-io") {
		t.Fatal("scope store aliases volumes")
	}
	for _, create := range []bool{false, true} {
		opts := windowsStorageIOOptions("fixture", create)
		volumes := windowsVolumeOptions("fixture", create)
		events := windowsEventOptions("fixture", create)
		metrics := windowsProcessMetricsOptions("fixture", create)
		if opts.LockName == metrics.LockName || opts.TempName == metrics.TempName {
			t.Fatal("network manifest aliases process metrics")
		}
		if opts.Create != create || opts.LockName == volumes.LockName || opts.TempName == volumes.TempName || opts.LockName == events.LockName || opts.TempName == events.TempName {
			t.Fatal("protected manifest is not isolated")
		}
	}
}

func TestWindowsStorageIOPreviewPreservesExistingRecord(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, enabled := range []bool{false, true} {
		consent := windowsstorageio.Consent{SchemaVersion: windowsstorageio.ConsentVersion, Scope: windowsstorageio.Scope, SenderBinding: binding, GrantID: strings.Repeat("b", 32), Enabled: enabled}
		raw, err := windowsstorageio.EncodeConsent(consent, binding)
		if err != nil {
			t.Fatal(err)
		}
		store := &storageIOConsentMemory{raw: raw}
		result, err := updateWindowsStorageIOConsent(binding, "preview", func(create bool) (storageIOConsentStore, error) {
			if create {
				t.Fatal("preview created state")
			}
			return store, nil
		})
		if err != nil || result.Enabled != enabled || result.Scope != windowsstorageio.Scope || !result.ExistingStatePreserved || store.writes != 0 || !store.closed || !bytes.Equal(store.raw, raw) {
			t.Fatal("preview changed grant", result, err)
		}
	}
}

func TestWindowsStorageIOInvalidRequestDoesNotReadHost(t *testing.T) {
	for _, mode := range []string{"", "future", "preview", "enable", "disable"} {
		for _, acknowledged := range []bool{false, true} {
			if (mode == "preview" || mode == "disable") && !acknowledged || mode == "enable" && acknowledged {
				continue // Valid requests need protected state; fixtures never touch it.
			}
			for _, insecure := range []bool{false, true} {
				if _, err := ConfigureWindowsStorageIO("never-opened", mode, acknowledged, insecure); err != ErrConfiguration {
					t.Fatal("invalid request reached host", mode, acknowledged, insecure, err)
				}
			}
		}
	}
	if _, enabled := readWindowsStorageIOConsent(Material{}); enabled {
		t.Fatal("invalid material permitted collection")
	}
	if _, err := updateWindowsStorageIOConsent(strings.Repeat("a", 64), "enable", nil); err != ErrConfiguration {
		t.Fatal("nil opener accepted")
	}
	if _, err := updateWindowsStorageIOConsent(strings.Repeat("a", 64), "unknown", func(bool) (storageIOConsentStore, error) {
		t.Fatal("invalid mode opened grant")
		return nil, nil
	}); err != ErrConfiguration {
		t.Fatal("invalid mode accepted")
	}
}
