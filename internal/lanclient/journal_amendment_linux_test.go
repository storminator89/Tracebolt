//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"localrmm/internal/journalgenerationstate"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalstate"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAmendmentAcceptPreservesOriginalIdentityAndConsumption(t *testing.T) {
	for _, mode := range []journalpolicy.ServiceAuthorization{"", journalpolicy.ExactUnits, journalpolicy.AllSystemServices} {
		t.Run("authorization="+string(mode), func(t *testing.T) { testAmendmentAcceptPreservesOriginalIdentityAndConsumption(t, mode) })
	}
}

func testAmendmentAcceptPreservesOriginalIdentityAndConsumption(t *testing.T, mode journalpolicy.ServiceAuthorization) {
	f := integrationFixture(t, "http-test", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	consumed, e := journalstate.Initialize(context.Background(), journalStateDirectory(m.config), m.binding)
	if e != nil {
		t.Fatal(e)
	}
	consumed.Close()
	originalPaths := []string{filepath.Join(m.config.StateDirectory, "state.json"), filepath.Join(m.config.StateDirectory, "inventory", "ledger.json"), filepath.Join(m.config.StateDirectory, "system", "system-state.json"), filepath.Join(journalStateDirectory(m.config), "journal-consumption.json")}
	before := map[string][]byte{}
	for _, p := range originalPaths {
		before[p], e = os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
	}
	identity := func() (uint32, uint32, bool) { return 1001, 1001, true }
	policy := journalpolicy.Policy{SchemaVersion: journalpolicy.Version, Scope: journalpolicy.Scope, CollectionProfile: journalpolicy.CollectionProfile, SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, TransportProfile: "http-test", AgentUID: 1001, HelperUID: 1002, AllowedUnits: []string{"docker.service", "ssh.service", "tracebolt-agent.service"}, MaxWindowSeconds: 3600, MaxLookbackSeconds: 86400, MaxPriority: 7, Enabled: true, ContentAcknowledged: true, PlaintextAcknowledged: true}
	local := journalLocal{policy: policy, revision: "synthetic-old"}
	loader := func(_ Material, uid, gid uint32, pending bool) (journalLocal, error) {
		if uid != 1001 || gid != 1001 {
			t.Fatal("identity changed")
		}
		return local, nil
	}
	preview, e := configureJournalAmendment(path, "preview", false, false, identity, loader)
	if e != nil || preview.Accepted || preview.PolicyDigest == "" {
		t.Fatal(e)
	}
	owner, e := openSenderState(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = configureJournalAmendment(path, "accept", true, true, identity, loader); e == nil {
		t.Fatal("active sender allowed amendment")
	}
	owner.Close()
	local.policy.SchemaVersion = journalpolicy.VersionV2
	local.policy.Revision = 1
	local.policy.Generation = strings.Repeat("c", 64)
	local.policy.AllowedUnits = append([]string{"cron.service"}, local.policy.AllowedUnits...)
	if mode != "" {
		local.policy.SchemaVersion = journalpolicy.VersionV3
		local.policy.Scope = journalpolicy.ScopeV3
		local.policy.ServiceAuthorization = mode
		if mode == journalpolicy.AllSystemServices {
			local.policy.AllowedUnits = []string{}
		}
	}
	local.generation, e = journalpolicy.PolicyGeneration(local.policy)
	if e != nil {
		t.Fatal(e)
	}
	local.revision = "synthetic-new"
	local.activationPhase = "pending"
	if _, e = configureJournalAmendment(path, "accept", true, false, identity, loader); e == nil {
		t.Fatal("HTTP ack omitted")
	}
	result, e := configureJournalAmendment(path, "accept", true, true, identity, loader)
	if e != nil || !result.Accepted || result.PolicyGeneration != local.generation || result.Scope != local.policy.Scope {
		t.Fatal(e)
	}
	if _, e = configureJournalAmendment(path, "accept", true, true, identity, loader); e == nil {
		t.Fatal("uncertain first migration adopted")
	}
	state, e := journalgenerationstate.Open(context.Background(), journalGenerationDirectory(m.config))
	if e != nil {
		t.Fatal(e)
	}
	r, _ := state.Record()
	state.Close()
	if r.PolicyGeneration != local.generation || r.SenderBinding != m.binding {
		t.Fatal("private tuple mismatch")
	}
	// Losing the first-generation private domain is not a supported reset:
	// committed activation must reject accept before recreating ReportSequence=0.
	local.activationPhase = "committed"
	if err := os.RemoveAll(journalGenerationDirectory(m.config)); err != nil {
		t.Fatal(err)
	}
	if _, err := configureJournalAmendment(path, "accept", true, true, identity, loader); err == nil {
		t.Fatal("committed activation reset missing private floor")
	}
	if _, err := os.Lstat(journalGenerationDirectory(m.config)); !os.IsNotExist(err) {
		t.Fatal("private floor recreated")
	}
	for p, want := range before {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("original state altered")
		}
	}
}
func TestAmendmentInvalidModesAndRootNeverReadState(t *testing.T) {
	calls := 0
	identity := func() (uint32, uint32, bool) { calls++; return 0, 0, false }
	loader := func(Material, uint32, uint32, bool) (journalLocal, error) {
		t.Fatal("local policy read")
		return journalLocal{}, nil
	}
	for _, mode := range []string{"", "initialize", "enable", "accept"} {
		if _, e := configureJournalAmendment("/never-read", mode, false, false, identity, loader); e == nil {
			t.Fatal("invalid mode accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid flags reached identity")
	}
	if _, e := configureJournalAmendment("/never-read", "preview", false, false, identity, loader); e == nil {
		t.Fatal("root accepted")
	}
}
