package lanclient

import (
	"bytes"
	"errors"
	"localrmm/internal/windowspatchcontext"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type patchContextConsentMemory struct {
	raw                         []byte
	writes                      int
	closed                      bool
	readErr, writeErr, closeErr error
}

func (s *patchContextConsentMemory) Read(name string) ([]byte, error) {
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
func (s *patchContextConsentMemory) Write(name string, b []byte) error {
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
func (s *patchContextConsentMemory) Close() error { s.closed = true; return s.closeErr }
func TestWindowsPatchContextConsentCreateOnlyAndReenable(t *testing.T) {
	binding := strings.Repeat("a", 64)
	store := &patchContextConsentMemory{}
	exists := false
	opens, creates := 0, 0
	open := func(create bool) (patchContextConsentStore, error) {
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
	r, e := updateWindowsPatchContextConsent(binding, "preview", open)
	if e != nil || r.Enabled || creates != 0 || store.writes != 0 {
		t.Fatal("preview wrote state", e)
	}
	r, e = updateWindowsPatchContextConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || store.writes != 1 || !store.closed {
		t.Fatal("fresh grant not committed", e)
	}
	first := bytes.Clone(store.raw)
	c, _ := windowspatchcontext.DecodeConsent(first, binding)
	r, e = updateWindowsPatchContextConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || !bytes.Equal(first, store.raw) {
		t.Fatal("repeated enable replaced grant")
	}
	r, e = updateWindowsPatchContextConsent(binding, "disable", open)
	if e != nil || r.Enabled {
		t.Fatal("disable failed")
	}
	off, _ := windowspatchcontext.DecodeConsent(store.raw, binding)
	if off.Enabled || off.GrantID != c.GrantID {
		t.Fatal("disable erased grant")
	}
	r, e = updateWindowsPatchContextConsent(binding, "enable", open)
	if e != nil || !r.Enabled {
		t.Fatal(e)
	}
	renewed, _ := windowspatchcontext.DecodeConsent(store.raw, binding)
	if renewed.GrantID == c.GrantID || creates != 1 || opens < 5 {
		t.Fatal("reenable reused revoked grant")
	}
}
func TestWindowsPatchContextConsentRejectsIncompleteForeignAndFailedStorage(t *testing.T) {
	binding := strings.Repeat("a", 64)
	c := windowspatchcontext.Consent{SchemaVersion: windowspatchcontext.ConsentVersion, Scope: windowspatchcontext.Scope, SenderBinding: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 32), Enabled: true}
	foreign, _ := windowspatchcontext.EncodeConsent(c, c.SenderBinding)
	for name, store := range map[string]*patchContextConsentMemory{"incomplete": {}, "foreign": {raw: foreign}, "malformed": {raw: []byte(`{}`)}, "read-failure": {readErr: errors.New("fixture")}} {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(store.raw)
			creates := 0
			_, e := updateWindowsPatchContextConsent(binding, "enable", func(create bool) (patchContextConsentStore, error) {
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
			store := &patchContextConsentMemory{}
			if failure == "write" {
				store.writeErr = ErrState
			} else {
				store.closeErr = ErrState
			}
			_, e := updateWindowsPatchContextConsent(binding, "enable", func(create bool) (patchContextConsentStore, error) {
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

func TestWindowsPatchContextConsentNeverCreatesOnPreviewDisableOrAccessFailure(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, mode := range []string{"preview", "disable"} {
		r, err := updateWindowsPatchContextConsent(binding, mode, func(create bool) (patchContextConsentStore, error) {
			if create {
				t.Fatal("non-enable created state")
			}
			return nil, os.ErrNotExist
		})
		if err != nil || r.Enabled || r.Scope != windowspatchcontext.Scope {
			t.Fatal("missing grant not default-off", err)
		}
	}
	for _, mode := range []string{"preview", "enable", "disable"} {
		_, err := updateWindowsPatchContextConsent(binding, mode, func(create bool) (patchContextConsentStore, error) {
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
		if _, err := ConfigureWindowsPatchContext("never-opened", mode, acknowledged, false); err != ErrConfiguration {
			t.Fatal("invalid ack reached host", err)
		}
	}
}
func TestWindowsPatchContextConsentSeparateProtectedManifest(t *testing.T) {
	opts := windowsPatchContextOptions("fixture-sid", false)
	events := windowsEventOptions("fixture-sid", false)
	if opts.RuntimeSID != "fixture-sid" || opts.Create || opts.MaxBytes != 1024 || len(opts.Names) != 1 || opts.Names[0] != "consent.json" || opts.LockName == events.LockName || opts.TempName == events.TempName {
		t.Fatal("network state not separately bounded")
	}
}

func TestWindowsPatchContextConsentMissingExistingRecordFailsClosedEveryMode(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		store := &patchContextConsentMemory{}
		calls := 0
		_, err := updateWindowsPatchContextConsent(strings.Repeat("a", 64), mode, func(create bool) (patchContextConsentStore, error) {
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

func TestWindowsPatchContextConsentFreshCreateRacesAndFailuresDoNotAdopt(t *testing.T) {
	for _, failure := range []error{os.ErrExist, os.ErrPermission, ErrState} {
		calls := 0
		_, err := updateWindowsPatchContextConsent(strings.Repeat("a", 64), "enable", func(create bool) (patchContextConsentStore, error) {
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
	_, err := updateWindowsPatchContextConsent(strings.Repeat("a", 64), "enable", func(bool) (patchContextConsentStore, error) { return nil, nil })
	if err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestWindowsPatchContextConsentStorageIsolation(t *testing.T) {
	m := Material{config: Config{StateDirectory: filepath.Join("fixture", "state", "sender", "runtime")}}
	network := windowsPatchContextConsentDirectory(m)
	if network == windowsVolumeConsentDirectory(m) || network == windowsProcessMetricsConsentDirectory(m) || !strings.HasSuffix(network, "-patch-context") {
		t.Fatal("scope store aliases volumes")
	}
	for _, create := range []bool{false, true} {
		opts := windowsPatchContextOptions("fixture", create)
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

func TestWindowsPatchContextPreviewPreservesExistingRecord(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, enabled := range []bool{false, true} {
		consent := windowspatchcontext.Consent{SchemaVersion: windowspatchcontext.ConsentVersion, Scope: windowspatchcontext.Scope, SenderBinding: binding, GrantID: strings.Repeat("b", 32), Enabled: enabled}
		raw, err := windowspatchcontext.EncodeConsent(consent, binding)
		if err != nil {
			t.Fatal(err)
		}
		store := &patchContextConsentMemory{raw: raw}
		result, err := updateWindowsPatchContextConsent(binding, "preview", func(create bool) (patchContextConsentStore, error) {
			if create {
				t.Fatal("preview created state")
			}
			return store, nil
		})
		if err != nil || result.Enabled != enabled || result.Scope != windowspatchcontext.Scope || !result.ExistingStatePreserved || store.writes != 0 || !store.closed || !bytes.Equal(store.raw, raw) {
			t.Fatal("preview changed grant", result, err)
		}
	}
}

func TestWindowsPatchContextInvalidRequestDoesNotReadHost(t *testing.T) {
	for _, mode := range []string{"", "future", "preview", "enable", "disable"} {
		for _, acknowledged := range []bool{false, true} {
			if (mode == "preview" || mode == "disable") && !acknowledged || mode == "enable" && acknowledged {
				continue // Valid requests need protected state; fixtures never touch it.
			}
			for _, insecure := range []bool{false, true} {
				if _, err := ConfigureWindowsPatchContext("never-opened", mode, acknowledged, insecure); err != ErrConfiguration {
					t.Fatal("invalid request reached host", mode, acknowledged, insecure, err)
				}
			}
		}
	}
	if _, enabled := readWindowsPatchContextConsent(Material{}); enabled {
		t.Fatal("invalid material permitted collection")
	}
	if _, err := updateWindowsPatchContextConsent(strings.Repeat("a", 64), "enable", nil); err != ErrConfiguration {
		t.Fatal("nil opener accepted")
	}
	if _, err := updateWindowsPatchContextConsent(strings.Repeat("a", 64), "unknown", func(bool) (patchContextConsentStore, error) {
		t.Fatal("invalid mode opened grant")
		return nil, nil
	}); err != ErrConfiguration {
		t.Fatal("invalid mode accepted")
	}
}
