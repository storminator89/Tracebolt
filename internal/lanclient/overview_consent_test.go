//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"localrmm/internal/overviewstate"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func overviewTestIdentity() (uint32, uint32, bool) { return 1001, 1001, true }
func overviewFileBytes(t *testing.T, paths []string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal("fixture state read")
		}
		out[p] = b
	}
	return out
}
func overviewFilesUnchanged(t *testing.T, before map[string][]byte) {
	t.Helper()
	for p, b := range before {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, b) {
			t.Fatal("existing private state changed")
		}
	}
}
func overviewExistingPaths(m Material) []string {
	return []string{m.config.PrivateKeyFile, m.config.CertificateFile, filepath.Join(m.config.StateDirectory, "state.json"), filepath.Join(inventoryStateDirectory(m.config), "ledger.json"), filepath.Join(systemStateDirectory(m.config), "system-state.json")}
}
func TestOverviewConsentStoppedIdentityExplicitScopeAndPreservedState(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	before := overviewFileBytes(t, overviewExistingPaths(m))
	owner, e := openSenderState(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = configureCompleteOverview(path, "enable", true, overviewTestIdentity); !errors.Is(e, ErrState) {
		t.Fatal("consent changed during running sender", e)
	}
	owner.Close()
	for _, mode := range []string{"preview", "enable", "preview"} {
		result, e := configureCompleteOverview(path, mode, mode == "enable", overviewTestIdentity)
		if e != nil || !result.ExistingStatePreserved || result.CaptureIntervalSeconds != 60 || !strings.Contains(result.Disclosure, "sensitive") || !strings.Contains(result.Disclosure, "namespaces") || !strings.Contains(result.Disclosure, "Full visible processes") {
			t.Fatal("explicit consent scope missing", e)
		}
		if mode == "enable" && !result.Enabled {
			t.Fatal("enable missing")
		}
		overviewFilesUnchanged(t, before)
	}
	states := []string{}
	for _, section := range []string{"processes", "volumes"} {
		state, e := overviewstate.OpenExisting(overviewStateDirectory(m.config, section), m.binding, m.config.AgentID, section)
		if e != nil {
			t.Fatal(e)
		}
		a, e := state.Allocate(context.Background(), time.Now().UTC())
		if e != nil || a.Sequence != 1 {
			t.Fatal("fixture allocation")
		}
		state.Close()
		states = append(states, filepath.Join(overviewStateDirectory(m.config, section), "ledger.json"))
	}
	domainBefore := overviewFileBytes(t, states)
	for _, mode := range []string{"disable", "enable", "disable"} {
		result, e := configureCompleteOverview(path, mode, mode == "enable", overviewTestIdentity)
		if e != nil || result.Enabled != (mode == "enable") {
			t.Fatal("toggle", mode, e)
		}
		overviewFilesUnchanged(t, domainBefore)
		overviewFilesUnchanged(t, before)
	}
}
func TestOverviewConsentIdentityAndAckBeforePrivateAccess(t *testing.T) {
	identityCalls := 0
	identity := func() (uint32, uint32, bool) { identityCalls++; return 0, 0, false }
	for _, mode := range []string{"", "other", "preview", "disable"} {
		if _, e := configureCompleteOverview("/never-read", mode, true, identity); !errors.Is(e, ErrConfiguration) {
			t.Fatal("invalid ack", e)
		}
	}
	if identityCalls != 0 {
		t.Fatal("invalid mode invoked identity")
	}
	if _, e := configureCompleteOverview("/never-read", "enable", true, identity); !errors.Is(e, ErrConfiguration) || identityCalls != 1 {
		t.Fatal("identity guard", e)
	}
}
func TestOverviewConsentIncompleteAndUncertainInitializationFailClosed(t *testing.T) {
	for _, scenario := range []string{"one-domain", "empty-pair", "init-marker", "consent-temp", "corrupt-domain", "foreign-section", "bad-consent"} {
		t.Run(scenario, func(t *testing.T) {
			f := integrationFixture(t, "tls", nil)
			m, path := prepareEndpointHandoff(t, f.material)
			old := overviewFileBytes(t, overviewExistingPaths(m))
			switch scenario {
			case "one-domain":
				s, e := overviewstate.InitializeNew(overviewStateDirectory(m.config, "processes"), m.binding, m.config.AgentID, "processes")
				if e != nil {
					t.Fatal(e)
				}
				s.Close()
			case "empty-pair":
				for _, section := range []string{"processes", "volumes"} {
					os.Mkdir(overviewStateDirectory(m.config, section), 0700)
				}
			case "init-marker":
				if beginOverviewInitialization(m) != nil {
					t.Fatal("marker")
				}
			case "consent-temp":
				os.WriteFile(filepath.Join(m.config.StateDirectory, overviewConsentTemp), []byte("uncertain"), 0600)
			case "corrupt-domain", "foreign-section":
				overviewConsentFixture(t, m)
				removeOverviewConsent(m)
				if scenario == "corrupt-domain" {
					os.WriteFile(filepath.Join(overviewStateDirectory(m.config, "processes"), "ledger.json"), []byte("corrupt"), 0600)
				} else {
					a, b := overviewStateDirectory(m.config, "processes"), overviewStateDirectory(m.config, "volumes")
					os.Rename(a, a+"-swap")
					os.Rename(b, a)
					os.Rename(a+"-swap", b)
				}
			case "bad-consent":
				os.WriteFile(filepath.Join(m.config.StateDirectory, overviewConsentName), []byte(`{"acknowledged":true}`), 0600)
			}
			if _, e := configureCompleteOverview(path, "enable", true, overviewTestIdentity); e == nil {
				t.Fatal("uncertain domain adopted")
			}
			if readOverviewConsent(m) {
				t.Fatal("uncertain initialization became enabled")
			}
			if _, e := configureCompleteOverview(path, "disable", false, overviewTestIdentity); e != nil {
				t.Fatal("disable blocked by bad extension state", e)
			}
			overviewFilesUnchanged(t, old)
			if scenario == "init-marker" {
				if _, e := os.Stat(filepath.Join(m.config.StateDirectory, overviewInitName)); e != nil {
					t.Fatal("init evidence removed")
				}
			}
			if scenario == "consent-temp" {
				if b, e := os.ReadFile(filepath.Join(m.config.StateDirectory, overviewConsentTemp)); e != nil || string(b) != "uncertain" {
					t.Fatal("uncertain evidence removed")
				}
			}
		})
	}
}
func TestOverviewConsentBoundToCurrentAgentLeafManagerAndProfile(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	m, _ := prepareEndpointHandoff(t, f.material)
	overviewConsentFixture(t, m)
	baseline := overviewConsentFor(m)
	for _, mutate := range []func(*overviewConsent){func(c *overviewConsent) { c.AgentID = "agent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, func(c *overviewConsent) { c.CertificateHash = strings.Repeat("0", 64) }, func(c *overviewConsent) { c.ManagerOrigin = "https://other.invalid" }, func(c *overviewConsent) { c.TransportProfile = "http-test" }, func(c *overviewConsent) { c.SenderBinding = strings.Repeat("1", 64) }, func(c *overviewConsent) { c.CaptureIntervalSeconds = 30 }, func(c *overviewConsent) { c.Acknowledged = false }} {
		candidate := baseline
		mutate(&candidate)
		raw, _ := json.Marshal(candidate)
		if os.WriteFile(filepath.Join(m.config.StateDirectory, overviewConsentName), raw, 0600) != nil {
			t.Fatal("fixture write")
		}
		if readOverviewConsent(m) {
			t.Fatal("foreign/altered consent accepted")
		}
	}
}

func TestOverviewExistingConsentRefusesBothMissingSequenceDomains(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	overviewConsentFixture(t, m)
	before := overviewFileBytes(t, append(overviewExistingPaths(m), filepath.Join(m.config.StateDirectory, overviewConsentName)))
	for _, section := range []string{"processes", "volumes"} {
		if e := os.RemoveAll(overviewStateDirectory(m.config, section)); e != nil {
			t.Fatal("remove fixture domain")
		}
	}
	if _, e := configureCompleteOverview(path, "enable", true, overviewTestIdentity); !errors.Is(e, ErrState) {
		t.Fatal("existing consent reset missing replay floors", e)
	}
	overviewFilesUnchanged(t, before)
	for _, section := range []string{"processes", "volumes"} {
		if _, e := os.Lstat(overviewStateDirectory(m.config, section)); !os.IsNotExist(e) {
			t.Fatal("missing domain recreated")
		}
	}
	if _, e := os.Lstat(filepath.Join(m.config.StateDirectory, overviewInitName)); !os.IsNotExist(e) {
		t.Fatal("reset initialization started")
	}
}
