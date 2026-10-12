package currentsetupgate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"localrmm/internal/lanclient"
	"localrmm/internal/windowsacceptance/fixture"
)

func authorized() (map[string]string, Binding, time.Time) {
	now := time.Unix(1900000000, 0)
	b := Binding{Source: strings.Repeat("a", 40), CompiledSource: strings.Repeat("a", 40), DriverHash: strings.Repeat("b", 64), SetupHash: strings.Repeat("c", 64), ServiceHash: strings.Repeat("d", 64), SourceInputsHash: strings.Repeat("e", 64), RunID: "12", Machine: "fresh-vm", Case: Cases[0], SourceTree: strings.Repeat("f", 40), CompiledTree: strings.Repeat("f", 40), MachineIDHash: strings.Repeat("1", 64), OSBuild: 26100, OSRevision: 100, Deadline: now.Add(14 * time.Minute)}
	e := map[string]string{"TRACEBOLT_SETUP_TREE": b.SourceTree, "TRACEBOLT_SETUP_MACHINE_ID_SHA256": b.MachineIDHash, "GITHUB_SHA": b.Source, "TRACEBOLT_SETUP_SOURCE": b.Source, "TRACEBOLT_SETUP_PROFILE": Profile, "TRACEBOLT_SETUP_CASE": b.Case, "TRACEBOLT_SETUP_MACHINE": b.Machine, "COMPUTERNAME": b.Machine, "GITHUB_REPOSITORY": "storminator89/Tracebolt", "GITHUB_REPOSITORY_OWNER": "storminator89", "GITHUB_REPOSITORY_OWNER_ID": "30489872", "GITHUB_ACTOR": "storminator89", "GITHUB_ACTOR_ID": "30489872", "GITHUB_TRIGGERING_ACTOR": "storminator89", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "RUNNER_OS": "Windows", "RUNNER_ARCH": "X64", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ID": "12", "TRACEBOLT_SETUP_RUN_ID": "12", "TRACEBOLT_SETUP_DRIVER_SHA256": b.DriverHash, "TRACEBOLT_SETUP_SETUP_SHA256": b.SetupHash, "TRACEBOLT_SETUP_SERVICE_SHA256": b.ServiceHash, "TRACEBOLT_SETUP_SOURCE_INPUTS_SHA256": b.SourceInputsHash}
	for _, a := range Approvals {
		e["TRACEBOLT_SETUP_APPROVE_"+a] = "true"
	}
	return e, b, now
}
func TestExactAuthorizationFailClosed(t *testing.T) {
	e, b, n := authorized()
	if Authorize(e, b, n) != nil {
		t.Fatal("valid inert binding rejected")
	}
	for key := range e {
		old := e[key]
		e[key] = ""
		if Authorize(e, b, n) == nil {
			t.Fatal("missing binding accepted", key)
		}
		e[key] = old
	}
	for _, a := range Approvals {
		e["TRACEBOLT_SETUP_APPROVE_"+a] = "false"
		if Authorize(e, b, n) == nil {
			t.Fatal("false approval")
		}
		e["TRACEBOLT_SETUP_APPROVE_"+a] = "true"
	}
	if Authorize(e, b, b.Deadline) == nil {
		t.Fatal("expired")
	}
}
func TestFiniteReportCoverageAndIndeterminateTruth(t *testing.T) {
	e, b, _ := authorized()
	_ = e
	for _, which := range Cases {
		b.Case = which
		r := NewReport(b)
		if r.Validate() != nil {
			t.Fatal("initial")
		}
		r.Status = "passed_packaged_gui_subset"
		r.Stage = "completed"
		r.Reason = "none"
		r.ApprovalValidated = true
		r.NativeActionsAttempted = true
		r.PlatformDisposalRequired = true
		r.Startup = "disabled"
		if NormalCase(which) {
			r.Startup = "absent"
			r.Frames = 2
			r.FrameProgress = currentGateFrameProgressFixture()
			r.ReceiptProof = currentReceiptProofFixture()
		}
		for k := range r.Checks {
			r.Checks[k] = true
		}
		if r.Validate() != nil {
			t.Fatal("pass")
		}
		r.Startup = "inspection_required"
		if r.Validate() == nil {
			t.Fatal("unknown startup passed")
		}
		r.Startup = "disabled"
		r.Coverage["humanUAC"] = true
		if r.Validate() == nil {
			t.Fatal("invented coverage")
		}
	}
}

func currentGateFrameProgressFixture() fixture.CurrentObservation {
	o := fixture.ZeroCurrentObservation()
	o.InitialCredentialGeneration = 1
	o.AcceptedFrames = 2
	o.LastSequence = 2
	o.V16Frames = 1
	o.LastFrameSHA256 = strings.Repeat("a", 64)
	for i := range o.Sources {
		s := &o.Sources[i]
		if s.Kind == "grant_only" {
			continue
		}
		s.Frames = 1
		s.Samples = 1
		s.LastSequence = 1
		s.LastFrameSHA256 = strings.Repeat("b", 64)
		s.Status = "observed"
		s.Qualities.Denied = 1
		if s.Kind == "independent" {
			s.Frames = 2
			s.Status = "source_failed"
			s.Reason = "access_denied"
		}
	}
	return o
}
func currentReceiptProofFixture() ReceiptProof {
	p := ReceiptProof{Verified: true, ReceiptSHA256: strings.Repeat("a", 64), ConsentSHA256: strings.Repeat("b", 64), SenderBinding: strings.Repeat("c", 64), ManifestSHA256: strings.Repeat("d", 64), CredentialGeneration: 1}
	for _, s := range lanclient.WindowsReadAdminScopesV14()[1:] {
		p.GrantDigests = append(p.GrantDigests, lanclient.WindowsCapabilityGrantDigest{Scope: s, SHA256: strings.Repeat("e", 64)})
	}
	raw, _ := json.Marshal(lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV14, CollectionProfile: "windows-inventory-v1", Scopes: lanclient.WindowsReadAdminScopesV14(), Acknowledged: true})
	h := sha256.Sum256(raw)
	p.ConsentSHA256 = hex.EncodeToString(h[:])
	return p
}
func TestCurrentGateNeverPromotesHistoricalProfilesOrScopeReceipt(t *testing.T) {
	e, b, n := authorized()
	for _, profile := range []string{"packaged-setup-gui-v1", "packaged-setup-gui-read-admin-v2"} {
		e["TRACEBOLT_SETUP_PROFILE"] = profile
		if Authorize(e, b, n) == nil {
			t.Fatal("old profile accepted")
		}
	}
	for _, old := range []string{"FIVE_READ_SCOPES", "TWELVE_READ_ADMIN_SCOPES", "HTTP_PLAINTEXT"} {
		e, b, n = authorized()
		e["TRACEBOLT_SETUP_APPROVE_"+old] = "true"
		if Authorize(e, b, n) == nil {
			t.Fatal("legacy approval accepted")
		}
	}
	p := currentReceiptProofFixture()
	if p.Validate() != nil {
		t.Fatal("current receipt rejected")
	}
	p.GrantDigests = p.GrantDigests[:4]
	if p.Validate() == nil {
		t.Fatal("old receipt accepted")
	}
}
func TestCurrentGateRetainsUnknownProviderTruth(t *testing.T) {
	p := currentGateFrameProgressFixture()
	if !p.Ready() {
		t.Fatal("denied source outcome erased")
	}
	for i, s := range p.Sources {
		if s.Kind == "grant_only" {
			continue
		}
		bad := p
		bad.Sources[i] = fixture.ZeroCurrentObservation().Sources[i]
		if bad.Ready() {
			t.Fatal("missing source promoted")
		}
	}
}
