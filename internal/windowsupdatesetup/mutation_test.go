package windowsupdatesetup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
)

func coordinatedSetupFixture(t *testing.T) (*setupFixture, CoordinatedMaterial) {
	t.Helper()
	f := newSetupFixture(t)
	d := func(s string) string { return actionpermit.Digest([]byte(s)) }
	var err error
	f.p, err = NewCoordinatedPlan(f.p, d("shared reviewed plan"))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{32}, 32))
	executor, grant := "executor_77777777777777777777777777777777", "grant_88888888888888888888888888888888"
	b := job.Binding{ManagerID: f.p.Offer.ManagerID, DeviceID: f.p.Offer.DeviceID, IncarnationDigest: f.p.Offer.IncarnationDigest, ExecutorID: executor, ExecutorKeyID: actionpermit.Digest(key.Public().(ed25519.PublicKey)), GrantID: grant, KeyID: actionpermit.Digest(f.p.Offer.ManagerPublicKey)}
	peer := fence.Participant{Domain: fence.ManagedMSI, BindingDigest: d("MSI binding"), GrantDigest: d("MSI grant"), ManagerKeyDigest: d("MSI manager"), ExecutorKeyDigest: d("MSI executor")}
	consent := job.Consent{Version: job.CoordinatedConsentVersion, Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.p.Offer.ExpiresAt, MutationPlanDigest: f.p.MutationPlanDigest, PeerBindingDigest: peer.BindingDigest}
	roster := fence.Roster{FenceID: d("created fence"), Plan: fence.Plan{Identity: fence.Identity{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest}, PlanDigest: f.p.MutationPlanDigest, MSIOfferDigest: d("MSI offer"), WUAOfferDigest: d("WUA offer"), MSIArtifactDigest: d("MSI artifact"), WUAArtifactDigest: d("WUA artifact")}, MSI: peer, WUA: job.MutationParticipant(consent)}
	if roster.Validate() != nil {
		t.Fatal("invalid fixture roster")
	}
	return f, CoordinatedMaterial{Roster: roster, Key: key, ExecutorID: executor, GrantID: grant}
}
func applyCoordinatedFixture(f *setupFixture, m CoordinatedMaterial) (job.SetupRegistration, error) {
	return apply(context.Background(), f.p, f.payload, Approval{Digest: f.p.Digest(), Install: true, Relay: true, ProcessQuery: true}, f.h, func() (ed25519.PrivateKey, string, string, error) {
		f.generated++
		return bytes.Clone(m.Key), m.ExecutorID, m.GrantID, nil
	}, func() time.Time { return f.now }, m)
}
func TestFreshCoordinatedUpdateSetupPinsRosterAndPreservesStandalone(t *testing.T) {
	f, m := coordinatedSetupFixture(t)
	r, e := applyCoordinatedFixture(f, m)
	if e != nil {
		t.Fatal(e)
	}
	c := f.config(t)
	if c.Version != windowsupdateipc.CoordinatedConfigVersion || c.Mutation == nil || *c.Mutation != m.Roster || r.Consent.Version != job.CoordinatedConsentVersion || r.Consent.ScheduleScope != "" || VerifyInstalled(f.s, c) != nil {
		t.Fatal("coordinated pins missing")
	}
	var ledger job.ExecutorRecord
	if json.Unmarshal(f.s.files["executor.json"], &ledger) != nil || ledger.Validate() != nil || ledger.Mutation == nil || *ledger.Mutation != m.Roster {
		t.Fatal("ledger did not bind roster")
	}
	legacy := newSetupFixture(t)
	if _, e = legacy.apply(); e != nil {
		t.Fatal(e)
	}
	old := legacy.config(t)
	if old.Version != windowsupdateipc.ConfigVersion || old.Mutation != nil || old.Consent.Version != job.ConsentVersion || bytes.Contains(legacy.s.files["config.json"], []byte("mutation")) {
		t.Fatal("standalone bytes promoted")
	}
	// Existing schedule consent cannot be silently removed or adopted.
	scheduled := newSetupFixture(t)
	scheduled.p.ScheduleScope = job.ScheduleScope
	scheduled.p.ScheduleDisclosure = ScheduleDisclosure
	if _, e = NewCoordinatedPlan(scheduled.p, f.p.MutationPlanDigest); e == nil {
		t.Fatal("scheduled grant adopted")
	}
}
func TestFreshCoordinatedUpdateSetupRejectsPairDriftAndKeepsPartialFence(t *testing.T) {
	f, m := coordinatedSetupFixture(t)
	m.Roster.Plan.PlanDigest = actionpermit.Digest([]byte("different"))
	if _, e := applyCoordinatedFixture(f, m); e == nil || f.created != 0 {
		t.Fatal("wrong shared plan reached writes")
	}
	f, m = coordinatedSetupFixture(t)
	f.s.fail = 4
	if _, e := applyCoordinatedFixture(f, m); e == nil || f.created != 1 || len(f.s.files["provision.json"]) == 0 || len(f.s.files["receipt.json"]) != 0 {
		t.Fatal("partial setup lost permanent intent or completed")
	}
}
