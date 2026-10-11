package lanclient

import (
	"encoding/json"
	"localrmm/internal/windowshistoryrequest"
	"localrmm/internal/windowsstate"
	"os"
	"reflect"
	"testing"
)

func TestWindowsReadAdminV14HistoryCannotPromoteOldConsent(t *testing.T) {
	c := WindowsCapabilityConsent{SchemaVersion: WindowsCapabilityConsentVersionV14, CollectionProfile: "windows-inventory-v1", Scopes: WindowsReadAdminScopesV14(), Acknowledged: true}
	if c.Validate() != nil || len(c.Scopes) != 21 || c.Scopes[20] != windowshistoryrequest.Scope || !reflect.DeepEqual(c.Scopes[:20], WindowsReadAdminScopesV13()) {
		t.Fatal("wrong exact scope set")
	}
	raw, _ := json.Marshal(c)
	if _, e := DecodeWindowsCapabilityConsent(raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []WindowsCapabilityConsent{{SchemaVersion: WindowsCapabilityConsentVersionV13, CollectionProfile: c.CollectionProfile, Scopes: c.Scopes, Acknowledged: true}, {SchemaVersion: c.SchemaVersion, CollectionProfile: c.CollectionProfile, Scopes: WindowsReadAdminScopesV13(), Acknowledged: true}, {SchemaVersion: c.SchemaVersion, CollectionProfile: c.CollectionProfile, Scopes: c.Scopes, Acknowledged: false}} {
		if bad.Validate() == nil {
			t.Fatal("old/unchecked consent authorized history")
		}
	}
	if _, e := ConfigureWindowsCapabilities("never-read", c); e != ErrConfiguration {
		t.Fatal("unguarded combined scope reached host")
	}
	if _, e := ConfigureWindowsReadAdminCapabilities("never-read", c, nil); e != ErrConfiguration {
		t.Fatal("missing receipt guard reached host")
	}
	roots := []string{}
	if e := windowsReadAdminScopesV14Absent("fixture", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		roots = append(roots, p)
		if o.Create {
			t.Fatal("preview created store")
		}
		return nil, os.ErrNotExist
	}); e != nil || len(roots) != 19 || roots[18] != "fixture-event-history" {
		t.Fatal("history root omission", e, roots)
	}
	if e := windowsReadAdminScopesV14Absent("fixture", "sid", func(p string, o windowsstate.Options) (capabilityInspectionStore, error) {
		if p == "fixture-event-history" {
			return nil, os.ErrPermission
		}
		return nil, os.ErrNotExist
	}); e == nil {
		t.Fatal("history denied root adopted")
	}
}
