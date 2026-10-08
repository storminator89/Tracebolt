package lanclient

import (
	"bytes"
	"errors"
	"localrmm/internal/windowsprocessmetrics"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type processMetricsConsentMemory struct {
	raw                         []byte
	writes                      int
	closed                      bool
	readErr, writeErr, closeErr error
}

func (s *processMetricsConsentMemory) Read(name string) ([]byte, error) {
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
func (s *processMetricsConsentMemory) Write(name string, b []byte) error {
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
func (s *processMetricsConsentMemory) Close() error { s.closed = true; return s.closeErr }
func TestWindowsProcessMetricsConsentCreateOnlyAndReenable(t *testing.T) {
	binding := strings.Repeat("a", 64)
	store := &processMetricsConsentMemory{}
	exists := false
	opens, creates := 0, 0
	open := func(create bool) (processMetricsConsentStore, error) {
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
	r, e := updateWindowsProcessMetricsConsent(binding, "preview", open)
	if e != nil || r.Enabled || creates != 0 || store.writes != 0 {
		t.Fatal("preview wrote state", e)
	}
	r, e = updateWindowsProcessMetricsConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || store.writes != 1 || !store.closed {
		t.Fatal("fresh grant not committed", e)
	}
	first := bytes.Clone(store.raw)
	c, _ := windowsprocessmetrics.DecodeConsent(first, binding)
	r, e = updateWindowsProcessMetricsConsent(binding, "enable", open)
	if e != nil || !r.Enabled || creates != 1 || !bytes.Equal(first, store.raw) {
		t.Fatal("repeated enable replaced grant")
	}
	r, e = updateWindowsProcessMetricsConsent(binding, "disable", open)
	if e != nil || r.Enabled {
		t.Fatal("disable failed")
	}
	off, _ := windowsprocessmetrics.DecodeConsent(store.raw, binding)
	if off.Enabled || off.GrantID != c.GrantID {
		t.Fatal("disable erased grant")
	}
	r, e = updateWindowsProcessMetricsConsent(binding, "enable", open)
	if e != nil || !r.Enabled {
		t.Fatal(e)
	}
	renewed, _ := windowsprocessmetrics.DecodeConsent(store.raw, binding)
	if renewed.GrantID == c.GrantID || creates != 1 || opens < 5 {
		t.Fatal("reenable reused revoked grant")
	}
}
func TestWindowsProcessMetricsConsentRejectsIncompleteForeignAndFailedStorage(t *testing.T) {
	binding := strings.Repeat("a", 64)
	c := windowsprocessmetrics.Consent{SchemaVersion: windowsprocessmetrics.ConsentVersion, Scope: windowsprocessmetrics.Scope, SenderBinding: strings.Repeat("b", 64), GrantID: strings.Repeat("c", 32), Enabled: true}
	foreign, _ := windowsprocessmetrics.EncodeConsent(c, c.SenderBinding)
	for name, store := range map[string]*processMetricsConsentMemory{"incomplete": {}, "foreign": {raw: foreign}, "malformed": {raw: []byte(`{}`)}, "read-failure": {readErr: errors.New("fixture")}} {
		t.Run(name, func(t *testing.T) {
			before := bytes.Clone(store.raw)
			creates := 0
			_, e := updateWindowsProcessMetricsConsent(binding, "enable", func(create bool) (processMetricsConsentStore, error) {
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
			store := &processMetricsConsentMemory{}
			if failure == "write" {
				store.writeErr = ErrState
			} else {
				store.closeErr = ErrState
			}
			_, e := updateWindowsProcessMetricsConsent(binding, "enable", func(create bool) (processMetricsConsentStore, error) {
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

func TestWindowsProcessMetricsConsentNeverCreatesOnPreviewDisableOrAccessFailure(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, mode := range []string{"preview", "disable"} {
		r, err := updateWindowsProcessMetricsConsent(binding, mode, func(create bool) (processMetricsConsentStore, error) {
			if create {
				t.Fatal("non-enable created state")
			}
			return nil, os.ErrNotExist
		})
		if err != nil || r.Enabled || r.Scope != windowsprocessmetrics.Scope {
			t.Fatal("missing grant not default-off", err)
		}
	}
	for _, mode := range []string{"preview", "enable", "disable"} {
		_, err := updateWindowsProcessMetricsConsent(binding, mode, func(create bool) (processMetricsConsentStore, error) {
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
		if _, err := ConfigureWindowsProcessMetrics("never-opened", mode, acknowledged, false); err != ErrConfiguration {
			t.Fatal("invalid ack reached host", err)
		}
	}
}
func TestWindowsProcessMetricsConsentSeparateProtectedManifest(t *testing.T) {
	opts := windowsProcessMetricsOptions("fixture-sid", false)
	events := windowsEventOptions("fixture-sid", false)
	if opts.RuntimeSID != "fixture-sid" || opts.Create || opts.MaxBytes != 1024 || len(opts.Names) != 1 || opts.Names[0] != "consent.json" || opts.LockName == events.LockName || opts.TempName == events.TempName {
		t.Fatal("process-metrics state not separately bounded")
	}
}

func TestWindowsProcessMetricsConsentMissingExistingRecordFailsClosedEveryMode(t *testing.T) {
	for _, mode := range []string{"preview", "enable", "disable"} {
		store := &processMetricsConsentMemory{}
		calls := 0
		_, err := updateWindowsProcessMetricsConsent(strings.Repeat("a", 64), mode, func(create bool) (processMetricsConsentStore, error) {
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

func TestWindowsProcessMetricsConsentFreshCreateRacesAndFailuresDoNotAdopt(t *testing.T) {
	for _, failure := range []error{os.ErrExist, os.ErrPermission, ErrState} {
		calls := 0
		_, err := updateWindowsProcessMetricsConsent(strings.Repeat("a", 64), "enable", func(create bool) (processMetricsConsentStore, error) {
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
	_, err := updateWindowsProcessMetricsConsent(strings.Repeat("a", 64), "enable", func(bool) (processMetricsConsentStore, error) { return nil, nil })
	if err == nil {
		t.Fatal("nil store accepted")
	}
}

func TestWindowsProcessMetricsConsentStorageIsolation(t *testing.T) {
	m := Material{config: Config{StateDirectory: filepath.Join("fixture", "state", "sender", "runtime")}}
	metrics := windowsProcessMetricsConsentDirectory(m)
	if metrics == windowsVolumeConsentDirectory(m) || !strings.HasSuffix(metrics, "-process-metrics") {
		t.Fatal("scope store aliases volumes")
	}
	for _, create := range []bool{false, true} {
		opts := windowsProcessMetricsOptions("fixture", create)
		volumes := windowsVolumeOptions("fixture", create)
		events := windowsEventOptions("fixture", create)
		if opts.Create != create || opts.LockName == volumes.LockName || opts.TempName == volumes.TempName || opts.LockName == events.LockName || opts.TempName == events.TempName {
			t.Fatal("protected manifest is not isolated")
		}
	}
}
