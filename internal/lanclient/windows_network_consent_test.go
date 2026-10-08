package lanclient

import (
	"bytes"
	"errors"
	"localrmm/internal/windowsnetwork"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type networkConsentMemory struct {
	raw                         []byte
	writes                      int
	closed                      bool
	readErr, writeErr, closeErr error
}

func (s *networkConsentMemory) Read(name string) ([]byte, error) {
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
func (s *networkConsentMemory) Write(name string, b []byte) error {
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
func (s *networkConsentMemory) Close() error { s.closed = true; return s.closeErr }
func TestWindowsNetworkConsentCreateOnlyAndReenable(t *testing.T) {
	binding := strings.Repeat("a", 64)
	store := &networkConsentMemory{}
	exists := false
	opens, creates := 0, 0
	open := func(create bool) (networkConsentStore, error) {
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
	r, e := updateWindowsNetworkConsent(binding, "preview", open)
	if e != nil || r.Enabled || creates != 0 || store.writes != 0 {
		t.Fatal("preview wrote state", e)
	}
	r, e = updateWindowsNetworkConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || store.writes != 1 || !store.closed {
		t.Fatal("fresh grant not committed", e)
	}
	first := bytes.Clone(store.raw)
	c, _ := windowsnetwork.DecodeConsent(first, binding)
	r, e = updateWindowsNetworkConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || !bytes.Equal(first, store.raw) {
		t.Fatal("repeated enable replaced grant")
	}
	r, e = updateWindowsNetworkConsent(binding, "disable", open)
	if e != nil || r.Enabled {
		t.Fatal("disable failed")
	}
	off, _ := windowsnetwork.DecodeConsent(store.raw, binding)
	if off.Enabled || off.GrantID != c.GrantID {
		t.Fatal("disable erased grant")
	}
	r, e = updateWindowsNetworkConsent(binding, "enable", open)
	if e != nil || !r.Enabled {
		t.Fatal(e)
	}
	renewed, _ := windowsnetwork.DecodeConsent(store.raw, binding)
	if renewed.GrantID == c.GrantID || creates != 1 || opens < 5 {
		t.Fatal("reenable reused revoked grant")
	}
}
func TestWindowsNetworkConsentRejectsIncompleteForeignAndFailedStorage(t *testing.T) {
	binding := strings.Repeat("a", 64)
	c := windowsnetwork.Consent{SchemaVersion: windowsnetwork.ConsentVersion, Scope: windowsnetwork.Scope, SenderBinding: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 32), Enabled: true}
	foreign, _ := windowsnetwork.EncodeConsent(c, c.SenderBinding)
	for name, store := range map[string]*networkConsentMemory{"incomplete": {}, "foreign": {raw: foreign}, "malformed": {raw: []byte(`{}`)}, "read-failure": {readErr: errors.New("fixture")}} {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(store.raw)
			creates := 0
			_, e := updateWindowsNetworkConsent(binding, "enable", func(create bool) (networkConsentStore, error) {
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
			store := &networkConsentMemory{}
			if failure == "write" {
				store.writeErr = ErrState
			} else {
				store.closeErr = ErrState
			}
			_, e := updateWindowsNetworkConsent(binding, "enable", func(create bool) (networkConsentStore, error) {
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

func TestWindowsNetworkConsentNeverCreatesOnPreviewDisableOrAccessFailure(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, mode := range []string{"preview", "disable"} {
		r, err := updateWindowsNetworkConsent(binding, mode, func(create bool) (networkConsentStore, error) {
			if create {
				t.Fatal("non-enable created state")
			}
			return nil, os.ErrNotExist
		})
		if err != nil || r.Enabled || r.Scope != windowsnetwork.Scope {
			t.Fatal("missing grant not default-off", err)
		}
	}
	for _, mode := range []string{"preview", "enable", "disable"} {
		_, err := updateWindowsNetworkConsent(binding, mode, func(create bool) (networkConsentStore, error) {
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
		if _, err := ConfigureWindowsNetwork("never-opened", mode, acknowledged, false); err != ErrConfiguration {
			t.Fatal("invalid ack reached host", err)
		}
	}
}
func TestWindowsNetworkConsentSeparateProtectedManifest(t *testing.T) {
	opts := windowsNetworkOptions("fixture-sid", false)
	events := windowsEventOptions("fixture-sid", false)
	if opts.RuntimeSID != "fixture-sid" || opts.Create || opts.MaxBytes != 1024 || len(opts.Names) != 1 || opts.Names[0] != "consent.json" || opts.LockName == events.LockName || opts.TempName == events.TempName {
		t.Fatal("network state not separately bounded")
	}
}

func TestWindowsNetworkConsentMissingExistingRecordFailsClosedEveryMode(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		store := &networkConsentMemory{}
		calls := 0
		_, err := updateWindowsNetworkConsent(strings.Repeat("a", 64), mode, func(create bool) (networkConsentStore, error) {
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

func TestWindowsNetworkConsentFreshCreateRacesAndFailuresDoNotAdopt(t *testing.T) {
	for _, failure := range []error{os.ErrExist, os.ErrPermission, ErrState} {
		calls := 0
		_, err := updateWindowsNetworkConsent(strings.Repeat("a", 64), "enable", func(create bool) (networkConsentStore, error) {
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
	_, err := updateWindowsNetworkConsent(strings.Repeat("a", 64), "enable", func(bool) (networkConsentStore, error) { return nil, nil })
	if err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestWindowsNetworkConsentStorageIsolation(t *testing.T) {
	m := Material{config: Config{StateDirectory: filepath.Join("fixture", "state", "sender", "runtime")}}
	network := windowsNetworkConsentDirectory(m)
	if network == windowsVolumeConsentDirectory(m) || network == windowsProcessMetricsConsentDirectory(m) || !strings.HasSuffix(network, "-network") {
		t.Fatal("scope store aliases volumes")
	}
	for _, create := range []bool{false, true} {
		opts := windowsNetworkOptions("fixture", create)
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

func TestWindowsNetworkPreviewPreservesExistingRecord(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, enabled := range []bool{false, true} {
		consent := windowsnetwork.Consent{SchemaVersion: windowsnetwork.ConsentVersion, Scope: windowsnetwork.Scope, SenderBinding: binding, GrantID: strings.Repeat("b", 32), Enabled: enabled}
		raw, err := windowsnetwork.EncodeConsent(consent, binding)
		if err != nil {
			t.Fatal(err)
		}
		store := &networkConsentMemory{raw: raw}
		result, err := updateWindowsNetworkConsent(binding, "preview", func(create bool) (networkConsentStore, error) {
			if create {
				t.Fatal("preview created state")
			}
			return store, nil
		})
		if err != nil || result.Enabled != enabled || result.Scope != windowsnetwork.Scope || !result.ExistingStatePreserved || store.writes != 0 || !store.closed || !bytes.Equal(store.raw, raw) {
			t.Fatal("preview changed grant", result, err)
		}
	}
}

func TestWindowsNetworkInvalidRequestDoesNotReadHost(t *testing.T) {
	for _, mode := range []string{"", "future", "preview", "enable", "disable"} {
		for _, acknowledged := range []bool{false, true} {
			if (mode == "preview" || mode == "disable") && !acknowledged || mode == "enable" && acknowledged {
				continue // Valid requests need protected state; fixtures never touch it.
			}
			for _, insecure := range []bool{false, true} {
				if _, err := ConfigureWindowsNetwork("never-opened", mode, acknowledged, insecure); err != ErrConfiguration {
					t.Fatal("invalid request reached host", mode, acknowledged, insecure, err)
				}
			}
		}
	}
	if _, enabled := readWindowsNetworkConsent(Material{}); enabled {
		t.Fatal("invalid material permitted collection")
	}
	if _, err := updateWindowsNetworkConsent(strings.Repeat("a", 64), "enable", nil); err != ErrConfiguration {
		t.Fatal("nil opener accepted")
	}
	if _, err := updateWindowsNetworkConsent(strings.Repeat("a", 64), "unknown", func(bool) (networkConsentStore, error) {
		t.Fatal("invalid mode opened grant")
		return nil, nil
	}); err != ErrConfiguration {
		t.Fatal("invalid mode accepted")
	}
}
