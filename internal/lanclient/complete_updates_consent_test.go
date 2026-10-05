//go:build linux

package lanclient

import (
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/cachedupdates"
	"localrmm/internal/inventorystate"
	"localrmm/internal/updategeneration"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func completeUpdatesConsentFixture(t *testing.T, m Material, path string) {
	t.Helper()
	if _, e := configureCompleteCachedUpdates(path, "enable", true, overviewTestIdentity); e != nil {
		t.Fatal("full consent fixture", e)
	}
}
func TestCompleteUpdatesConsentStoppedIdentityAndIndependentFloor(t *testing.T) {
	if cachedupdates.CompleteSchemaVersion != updategeneration.SchemaVersion || cachedupdates.CompleteScope != updategeneration.Scope {
		t.Fatal("full consent adapter drift")
	}
	f := integrationFixture(t, "tls", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	cachedUpdatesConsentFixture(t, m)
	paths := append(overviewExistingPaths(m), cachedUpdatesConsentPath(m))
	before := overviewFileBytes(t, paths)
	owner, e := openSenderState(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = configureCompleteCachedUpdates(path, "enable", true, overviewTestIdentity); !errors.Is(e, ErrState) {
		t.Fatal("running sender permitted grant")
	}
	owner.Close()
	result, e := configureCompleteCachedUpdates(path, "preview", false, overviewTestIdentity)
	if e != nil || result.Enabled || !strings.Contains(result.Disclosure, "All known") || result.CaptureIntervalSeconds != 21600 {
		t.Fatal("scope disclosure or default", e)
	}
	if _, e := os.Stat(completeUpdatesStateDirectory(m.config)); !os.IsNotExist(e) {
		t.Fatal("preview opened state")
	}
	completeUpdatesConsentFixture(t, m, path)
	state, e := inventorystate.OpenCachedUpdatesExisting(completeUpdatesStateDirectory(m.config), completeUpdatesStateBinding(m), m.config.AgentID)
	if e != nil {
		t.Fatal(e)
	}
	a, e := state.Allocate(context.Background(), time.Now().UTC())
	if e != nil || a.Sequence != 1 {
		t.Fatal("floor fixture", e)
	}
	state.Close()
	domain := overviewFileBytes(t, []string{filepath.Join(completeUpdatesStateDirectory(m.config), "ledger.json")})
	for _, mode := range []string{"disable", "enable", "disable"} {
		result, e := configureCompleteCachedUpdates(path, mode, mode == "enable", overviewTestIdentity)
		if e != nil || result.Enabled != (mode == "enable") || !result.ExistingStatePreserved {
			t.Fatal("full consent toggle", mode, e)
		}
		overviewFilesUnchanged(t, before)
		overviewFilesUnchanged(t, domain)
	}
	if _, ok := readCachedUpdatesConsent(m); !ok {
		t.Fatal("full consent changed preview consent")
	}
	if _, ok := readCompleteUpdatesConsent(m); ok {
		t.Fatal("disabled full grant returned")
	}
}
func TestCompleteUpdatesConsentFailsClosedWithoutSourceOrSpoolAccess(t *testing.T) {
	for _, scenario := range []string{"missing", "preview-grant", "preview", "foreign", "unsafe", "init-marker", "uncertain-temp"} {
		t.Run(scenario, func(t *testing.T) {
			f := integrationFixture(t, "tls", nil)
			m, _ := prepareEndpointHandoff(t, f.material)
			c := completeUpdatesConsentFor(m)
			switch scenario {
			case "preview-grant":
				cachedUpdatesConsentFixture(t, m)
			case "preview":
				p := cachedupdates.LocalConsent(c)
				p.SchemaVersion, p.ExtensionVersion, p.Scope = cachedupdates.ConsentVersion, cachedupdates.SchemaVersion, cachedupdates.Scope
				raw, _ := json.Marshal(p)
				os.WriteFile(filepath.Join(m.config.StateDirectory, completeUpdatesConsentName), raw, 0600)
			case "foreign":
				c.SenderBinding = strings.Repeat("a", 64)
				raw, _ := json.Marshal(c)
				os.WriteFile(filepath.Join(m.config.StateDirectory, completeUpdatesConsentName), raw, 0600)
			case "unsafe", "init-marker", "uncertain-temp":
				raw, _ := cachedupdates.EncodeCompleteLocalConsent(c, m.binding)
				os.WriteFile(filepath.Join(m.config.StateDirectory, completeUpdatesConsentName), raw, 0600)
				if scenario == "unsafe" {
					os.Chmod(filepath.Join(m.config.StateDirectory, completeUpdatesConsentName), 0644)
				}
				if scenario == "init-marker" {
					beginCompleteUpdatesInitialization(m)
				}
				if scenario == "uncertain-temp" {
					os.WriteFile(filepath.Join(m.config.StateDirectory, completeUpdatesConsentTemp), []byte("preserve"), 0600)
				}
			}
			// Even a corrupt fixed spool must be ignored without valid full consent.
			os.WriteFile(completeUpdatesStateDirectory(m.config), []byte("not a directory"), 0600)
			calls := 0
			s, e := openCompleteUpdatesSenderWithSource(m, time.Now, func(context.Context, string, time.Time, cachedupdates.CompleteLocalConsent, string) (cachedupdates.CompleteSource, error) {
				calls++
				return cachedupdates.CompleteSource{}, nil
			})
			if e != nil || s != nil || calls != 0 {
				t.Fatal("default-off source or spool access", e)
			}
		})
	}
}
func TestCompleteUpdatesConsentCannotResetMissingOrForeignSpool(t *testing.T) {
	for _, scenario := range []string{"missing", "foreign", "empty", "uncertain"} {
		t.Run(scenario, func(t *testing.T) {
			f := integrationFixture(t, "tls", nil)
			m, path := prepareEndpointHandoff(t, f.material)
			if scenario == "missing" {
				raw, _ := cachedupdates.EncodeCompleteLocalConsent(completeUpdatesConsentFor(m), m.binding)
				os.WriteFile(filepath.Join(m.config.StateDirectory, completeUpdatesConsentName), raw, 0600)
			} else if scenario == "empty" {
				os.Mkdir(completeUpdatesStateDirectory(m.config), 0700)
			} else if scenario == "uncertain" {
				beginCompleteUpdatesInitialization(m)
			} else {
				state, e := inventorystate.InitializeNew(completeUpdatesStateDirectory(m.config), m.binding, m.config.AgentID)
				if e != nil {
					t.Fatal(e)
				}
				state.Close()
			}
			before := overviewFileBytes(t, overviewExistingPaths(m))
			if _, e := configureCompleteCachedUpdates(path, "enable", true, overviewTestIdentity); !errors.Is(e, ErrState) {
				t.Fatal("reset/adopted missing or foreign floor", e)
			}
			overviewFilesUnchanged(t, before)
		})
	}
}
