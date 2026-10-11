//go:build linux

package lanclient

import (
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsstorageio"
	"reflect"
	"strings"
	"testing"
)

func TestWindowsStorageIOConsentRequiresCurrentActivatedIdentityBeforeRead(t *testing.T) {
	for _, kind := range []string{"identity-replaced", "config-replaced", "ready-removed", "ready-replaced", "load-denied"} {
		t.Run(kind, func(t *testing.T) {
			m, reload, change := windowsActivatedMaterialFixture(t)
			consent := windowsstorageio.Consent{SchemaVersion: windowsstorageio.ConsentVersion, Scope: windowsstorageio.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("a", 32), Enabled: true}
			raw, err := windowsstorageio.EncodeConsent(consent, m.binding)
			if err != nil {
				t.Fatal(err)
			}
			deps := windowsContextConsentDependencies{reload, func(path string, opts windowsstate.Options) (windowsContextConsentStore, error) {
				if path != windowsStorageIOConsentDirectory(m) || !reflect.DeepEqual(opts, windowsStorageIOOptions("", false)) {
					t.Fatal("wrong protected scope")
				}
				return &storageIOConsentMemory{raw: raw}, nil
			}}
			if got, ok := readWindowsStorageIOConsentWithDependencies(m, deps); !ok || got != consent {
				t.Fatal("current authority rejected")
			}
			change(kind)
			deps.open = func(string, windowsstate.Options) (windowsContextConsentStore, error) {
				t.Fatal("stale identity opened consent")
				return nil, nil
			}
			if _, ok := readWindowsStorageIOConsentWithDependencies(m, deps); ok {
				t.Fatal("stale authority accepted")
			}
		})
	}
}

func TestWindowsStorageIOConsentReadFailuresRemainDefaultOff(t *testing.T) {
	m, reload, _ := windowsActivatedMaterialFixture(t)
	good := windowsstorageio.Consent{SchemaVersion: windowsstorageio.ConsentVersion, Scope: windowsstorageio.Scope, SenderBinding: m.binding, GrantID: strings.Repeat("b", 32), Enabled: true}
	for _, kind := range []string{"missing-root", "denied-root", "missing-record", "malformed", "disabled", "foreign", "close-failed", "nil-opener", "nil-store"} {
		t.Run(kind, func(t *testing.T) {
			consent := good
			if kind == "disabled" {
				consent.Enabled = false
			}
			if kind == "foreign" {
				consent.SenderBinding = strings.Repeat("0", 64)
			}
			raw, err := windowsstorageio.EncodeConsent(consent, consent.SenderBinding)
			if err != nil {
				t.Fatal(err)
			}
			store := &storageIOConsentMemory{raw: raw}
			switch kind {
			case "missing-record":
				store.raw = nil
			case "malformed":
				store.raw = []byte(`{}`)
			case "close-failed":
				store.closeErr = ErrState
			}
			deps := windowsContextConsentDependencies{reload, func(_ string, opts windowsstate.Options) (windowsContextConsentStore, error) {
				if opts.Create {
					t.Fatal("read created scope")
				}
				if kind == "nil-store" {
					return nil, nil
				}
				if kind == "missing-root" || kind == "denied-root" {
					return nil, ErrState
				}
				return store, nil
			}}
			if kind == "nil-opener" {
				deps.open = nil
			}
			if _, enabled := readWindowsStorageIOConsentWithDependencies(m, deps); enabled || store.writes != 0 {
				t.Fatal("failed consent granted collection or wrote state")
			}
		})
	}
}
