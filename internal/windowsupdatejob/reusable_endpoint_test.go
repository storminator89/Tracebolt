package windowsupdatejob

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"localrmm/internal/actionpermit"
	fence "localrmm/internal/windowsmutationfence"
)

func freshReusableExecutorRecord(t *testing.T) ExecutorRecord {
	t.Helper()
	f := fixture(t)
	c := f.consent
	c.Version = ReusableConsentVersion
	c.BackgroundAcknowledged = true
	c.ReusableAcknowledged = true
	c.MutationPlanDigest = actionpermit.Digest([]byte("reusable exact plan"))
	c.PeerBindingDigest = actionpermit.Digest([]byte("independent MSI binding"))
	d := func(v string) string { return actionpermit.Digest([]byte(v)) }
	r := fence.Roster{Version: fence.ReusableWUARosterVersion, FenceID: d("fence"), Plan: fence.Plan{Version: fence.ReusableWUAPlanVersion, Identity: fence.Identity{ManagerID: c.Binding.ManagerID, DeviceID: c.Binding.DeviceID, IncarnationDigest: c.Binding.IncarnationDigest}, PlanDigest: c.MutationPlanDigest, MSIOfferDigest: d("MSI offer"), WUAOfferDigest: d("WUA offer"), MSIArtifactDigest: d("MSI image"), WUAArtifactDigest: d("WUA image")}, MSI: fence.Participant{Domain: fence.ManagedMSI, BindingDigest: c.PeerBindingDigest, GrantDigest: d("MSI grant"), ManagerKeyDigest: d("MSI manager key"), ExecutorKeyDigest: d("MSI executor key")}, WUA: MutationParticipant(c)}
	record, e := NewCoordinatedExecutorRecord(c, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix(), r)
	if e != nil {
		t.Fatal(e)
	}
	return record
}
func TestReusableExecutorFreshVersionStateAndOldBytes(t *testing.T) {
	f := fixture(t)
	old, e := NewExecutorRecord(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := EncodeExecutorRecord(old)
	if e != nil || bytes.Contains(raw, []byte(`"reusable"`)) {
		t.Fatal("old ledger bytes expanded", e)
	}
	old.Reusable = newReusableExecutorState()
	if old.Validate() == nil {
		t.Fatal("old ledger adopted reusable floor")
	}
	fresh := freshReusableExecutorRecord(t)
	if fresh.Version != ReusableExecutorVersion || fresh.Reusable == nil || fresh.Reusable.RetiredFloor != 0 || len(fresh.Reusable.Recent) != 0 {
		t.Fatal("fresh reusable state missing")
	}
	for _, mutation := range []string{"missing_state", "old_version", "missing_ack", "changed_roster", "floor", "chain", "nil_recent", "pending_without_attempt"} {
		t.Run(mutation, func(t *testing.T) {
			encoded, _ := json.Marshal(fresh)
			var r ExecutorRecord
			_ = json.Unmarshal(encoded, &r)
			switch mutation {
			case "missing_state":
				r.Reusable = nil
			case "old_version":
				r.Version = CoordinatedExecutorVersion
			case "missing_ack":
				r.Consent.ReusableAcknowledged = false
			case "changed_roster":
				r.Mutation.Version = fence.BackgroundRosterVersion
				r.Mutation.Plan.Version = fence.BackgroundPlanVersion
			case "floor":
				r.Reusable.RetiredFloor = 1
			case "chain":
				r.Reusable.RetiredChain = actionpermit.Digest([]byte("changed"))
			case "nil_recent":
				r.Reusable.Recent = nil
			case "pending_without_attempt":
				r.Reusable.Pending = []byte("unbound intent")
			}
			if r.Validate() == nil {
				t.Fatal("invalid reusable state accepted")
			}
		})
	}
}
func TestReusableReadinessMissingPreRetirementEvidenceRejected(t *testing.T) {
	r := freshReusableExecutorRecord(t)
	r.ReadinessSequence = 42
	if r.Validate() == nil {
		t.Fatal("missing used readiness evidence admitted before any retirement")
	}
	// Only a proved retirement can clear the advertised slot while preserving
	// its scalar. Full retired-history validation is exercised by signed flows.
	r.Reusable.RetiredFloor = 1
	if r.validateReadiness() != nil {
		t.Fatal("retirement cannot retain a cleared readiness floor")
	}
	r.Reusable = nil
	if r.validateReadiness() == nil {
		t.Fatal("legacy missing readiness slot promoted")
	}
}
