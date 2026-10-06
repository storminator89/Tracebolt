//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"localrmm/internal/journalgeneration"
	"localrmm/internal/journalgenerationstate"
	"localrmm/internal/journalhelper"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalstate"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalConsentAdminCreateOnlyAndExistingLedgersUntouched(t *testing.T) {
	f := integrationFixture(t, "http-test", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	identity := func() (uint32, uint32, bool) { return 1001, 1001, true }
	localCalls := 0
	local := func(Material) (journalLocal, error) { localCalls++; return initialJournalFixture(t, m, false), nil }
	paths := []string{filepath.Join(m.config.StateDirectory, "state.json"), filepath.Join(m.config.StateDirectory, "inventory", "ledger.json"), filepath.Join(m.config.StateDirectory, "system", "system-state.json")}
	before := map[string][]byte{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		before[p] = b
	}
	preview, e := configureJournalContent(path, "preview", false, false, identity, local)
	if e != nil || preview.SenderBinding != m.binding || preview.Initialized || localCalls != 0 {
		t.Fatal("preview altered or required policy", e)
	}
	owner, e := openSenderState(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := configureJournalContent(path, "initialize", true, true, identity, local); e == nil {
		t.Fatal("active sender allowed initialization")
	}
	owner.Close()
	if _, e := configureJournalContent(path, "initialize", true, false, identity, local); e == nil {
		t.Fatal("missing separate plaintext acknowledgement accepted")
	}
	result, e := configureJournalContent(path, "initialize", true, true, identity, local)
	if e != nil || !result.Initialized || !result.ExistingStatePreserved {
		t.Fatal("initialization failed", e)
	}
	if _, e := configureJournalContent(path, "initialize", true, true, identity, local); e == nil {
		t.Fatal("existing marker reset")
	}
	for p, want := range before {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("existing ledger altered")
		}
	}
}

func initialJournalFixture(t *testing.T, m Material, broad bool) journalLocal {
	t.Helper()
	p := journalpolicy.Policy{SchemaVersion: journalpolicy.Version, Scope: journalpolicy.Scope, CollectionProfile: journalpolicy.CollectionProfile, SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, TransportProfile: m.config.Profile, AgentUID: 1001, HelperUID: 1002, AllowedUnits: []string{"example.service"}, MaxWindowSeconds: 3600, MaxLookbackSeconds: 86400, MaxPriority: 7, Enabled: true, ContentAcknowledged: true, PlaintextAcknowledged: m.config.Profile == "http-test"}
	local := journalLocal{policy: p, revision: "synthetic-initial"}
	if broad {
		local.policy.SchemaVersion = journalpolicy.VersionV3
		local.policy.Scope = journalpolicy.ScopeV3
		local.policy.ServiceAuthorization = journalpolicy.AllSystemServices
		local.policy.Revision = 1
		local.policy.Generation = strings.Repeat("c", 64)
		local.policy.AllowedUnits = []string{}
		local.activationPhase = "pending"
		local.deployment = journalhelper.Deployment{SchemaVersion: journalhelper.DeploymentVersionV2, HelperUID: 1002, HelperGID: 1002, JournalGID: 1003, AgentUID: 1001, AgentGID: 1001, PolicyGenerationRequired: true}
		var err error
		local.generation, err = journalpolicy.PolicyGeneration(local.policy)
		if err != nil {
			t.Fatal(err)
		}
	}
	return local
}

func TestJournalConsentFreshBroadInitializesBothFloorsCreateOnly(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := integrationFixture(t, profile, nil)
			m, path := prepareEndpointHandoff(t, f.material)
			current := initialJournalFixture(t, m, true)
			calls := 0
			local := func(Material) (journalLocal, error) { calls++; return current, nil }
			identity := func() (uint32, uint32, bool) { return 1001, 1001, true }
			paths := []string{filepath.Join(m.config.StateDirectory, "state.json"), filepath.Join(m.config.StateDirectory, "inventory", "ledger.json"), filepath.Join(m.config.StateDirectory, "system", "system-state.json")}
			before := map[string][]byte{}
			for _, p := range paths {
				var err error
				before[p], err = os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
			}
			result, err := configureJournalContent(path, "initialize", true, profile == "http-test", identity, local)
			if err != nil || !result.Initialized || !result.ExistingStatePreserved || result.Scope != journalpolicy.ScopeV3 || result.PolicyGeneration != current.generation || calls != 2 {
				t.Fatal("fresh generation not confirmed", err, result)
			}
			state, err := journalstate.Open(context.Background(), journalStateDirectory(m.config), m.binding)
			if err != nil {
				t.Fatal(err)
			}
			floor, err := state.SequenceFloor()
			if err != nil || floor != 0 || state.Close() != nil {
				t.Fatal("unexpected consumed floor", err)
			}
			generation, err := journalgenerationstate.Open(context.Background(), journalGenerationDirectory(m.config))
			if err != nil {
				t.Fatal(err)
			}
			record, err := generation.Record()
			if err != nil || record.PolicyGeneration != current.generation || record.ReportSequence != 0 || record.SenderBinding != m.binding || record.DeviceID != m.config.AgentID || record.CertificateHash != journalLeaf(m) || generation.Close() != nil {
				t.Fatal("unexpected generation floor", err)
			}
			for _, p := range []string{filepath.Join(journalStateDirectory(m.config), "journal-consumption.json"), filepath.Join(journalGenerationDirectory(m.config), "journal-generation.json")} {
				before[p], err = os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = configureJournalContent(path, "initialize", true, profile == "http-test", identity, local); err == nil {
				t.Fatal("existing floors adopted")
			}
			for p, expected := range before {
				actual, err := os.ReadFile(p)
				if err != nil || !bytes.Equal(actual, expected) {
					t.Fatal("existing state changed", err)
				}
			}
		})
	}
}

func TestJournalConsentFreshBroadRejectsInvalidAuthorityBeforeFloorCreation(t *testing.T) {
	changes := map[string]func(*journalLocal){
		"committed":                      func(l *journalLocal) { l.activationPhase = "committed" },
		"absent":                         func(l *journalLocal) { l.activationPhase = "" },
		"old-deployment":                 func(l *journalLocal) { l.deployment.SchemaVersion = journalhelper.DeploymentVersion },
		"missing-generation-requirement": func(l *journalLocal) { l.deployment.PolicyGenerationRequired = false },
		"changed-tuple":                  func(l *journalLocal) { l.generation.PolicyDigest = "sha256:" + strings.Repeat("d", 64) },
		"zero-tuple":                     func(l *journalLocal) { l.generation = journalgeneration.Tuple{} },
		"wrong-binding":                  func(l *journalLocal) { l.policy.SenderBinding = strings.Repeat("d", 64) },
		"disabled": func(l *journalLocal) {
			l.policy.Enabled = false
			l.generation, _ = journalpolicy.PolicyGeneration(l.policy)
		},
		"later-revision": func(l *journalLocal) {
			l.policy.Revision = 2
			l.generation, _ = journalpolicy.PolicyGeneration(l.policy)
		},
		"exact-units-v3": func(l *journalLocal) {
			l.policy.ServiceAuthorization = journalpolicy.ExactUnits
			l.policy.AllowedUnits = []string{"example.service"}
			l.generation, _ = journalpolicy.PolicyGeneration(l.policy)
		},
		"v2": func(l *journalLocal) {
			l.policy.SchemaVersion = journalpolicy.VersionV2
			l.policy.Scope = journalpolicy.Scope
			l.policy.ServiceAuthorization = ""
			l.policy.AllowedUnits = []string{"example.service"}
			l.generation, _ = journalpolicy.PolicyGeneration(l.policy)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			f := integrationFixture(t, "http-test", nil)
			m, path := prepareEndpointHandoff(t, f.material)
			current := initialJournalFixture(t, m, true)
			change(&current)
			_, err := configureJournalContent(path, "initialize", true, true, func() (uint32, uint32, bool) { return 1001, 1001, true }, func(Material) (journalLocal, error) { return current, nil })
			if err == nil {
				t.Fatal("invalid initial authority accepted")
			}
			for _, dir := range []string{journalStateDirectory(m.config), journalGenerationDirectory(m.config)} {
				if _, err := os.Lstat(dir); !os.IsNotExist(err) {
					t.Fatal("private state created before validation", dir)
				}
			}
		})
	}
}

func TestJournalConsentFreshBroadRejectsEitherExistingDomainAndRetainsChangedAttempt(t *testing.T) {
	for _, kind := range []string{"journal", "generation", "changed-authority"} {
		t.Run(kind, func(t *testing.T) {
			f := integrationFixture(t, "http-test", nil)
			m, path := prepareEndpointHandoff(t, f.material)
			current := initialJournalFixture(t, m, true)
			journalDir, generationDir := journalStateDirectory(m.config), journalGenerationDirectory(m.config)
			if kind != "changed-authority" {
				dir := journalDir
				if kind == "generation" {
					dir = generationDir
				}
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			loader := func(Material) (journalLocal, error) {
				calls++
				copy := current
				if kind == "changed-authority" && calls > 1 {
					copy.revision = "changed"
				}
				return copy, nil
			}
			identity := func() (uint32, uint32, bool) { return 1001, 1001, true }
			if _, err := configureJournalContent(path, "initialize", true, true, identity, loader); err == nil {
				t.Fatal("partial/changed state accepted")
			}
			if kind != "changed-authority" {
				other := generationDir
				if kind == "generation" {
					other = journalDir
				}
				if _, err := os.Lstat(other); !os.IsNotExist(err) {
					t.Fatal("missing domain reconstructed")
				}
			} else {
				for _, dir := range []string{journalDir, generationDir} {
					if _, err := os.Lstat(dir); err != nil {
						t.Fatal("failed attempt evidence lost", err)
					}
				}
				if _, err := configureJournalContent(path, "initialize", true, true, identity, loader); err == nil {
					t.Fatal("failed attempt adopted")
				}
			}
		})
	}
}
func TestJournalConsentRootOrInvalidIdentityRejected(t *testing.T) {
	called := false
	_, e := configureJournalContent("/never-read", "preview", false, false, func() (uint32, uint32, bool) { return 0, 0, false }, func(Material) (journalLocal, error) { called = true; return journalLocal{}, nil })
	if e == nil || called {
		t.Fatal("invalid identity reached policy")
	}
}
