package windowsupdatejob

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	fence "localrmm/internal/windowsmutationfence"
	"testing"
	"time"
)

func TestCoordinatedApprovalRequiresFreshIdleStatusWithoutConsuming(t *testing.T) {
	for _, state := range []string{"missing", "blocked", "unknown", "stale", "idle"} {
		t.Run(state, func(t *testing.T) {
			f := fixture(t)
			f.consent.Version = CoordinatedConsentVersion
			f.consent.MutationPlanDigest = actionpermit.Digest([]byte("plan"))
			f.consent.PeerBindingDigest = actionpermit.Digest([]byte("peer"))
			// Construct a fresh coordinated manager fixture, never adopt production state.
			r, e := NewRecordWithExecutor(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := EncodeRecord(r)
			c, _ := json.Marshal(f.consent)
			f.store.files["jobs.json"] = raw
			f.store.files["started.json"] = c
			f.store.files["receipt.json"] = c
			f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
			if e != nil {
				t.Fatal(e)
			}
			f.request(t)
			p := f.m.record.Jobs[0].Preview
			if state != "missing" {
				status := fence.Status{Active: true, Phase: "idle", Revision: 7, Retained: 1}
				if state == "blocked" {
					status.Blocked = true
					status.Domain = fence.ManagedMSI
					status.JobID = "transfer_88888888888888888888888888888888"
					status.Phase = "dispatch_intent"
					status.Recovery = "intervention_required"
				}
				if state == "unknown" {
					status = fence.Status{Blocked: true, Phase: "unavailable", Recovery: "intervention_required"}
				}
				at := f.at.Unix()
				if state == "stale" {
					at -= 60
				}
				challenge := f.m.record.Jobs[0].Challenge
				ch, _ := VerifyChallenge(challenge, f.key.Public().(ed25519.PublicKey))
				statement := Statement{Version: RelayVersion, Kind: "mutation", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: actionpermit.Digest(challenge), Deadline: ch.Deadline, IssuedAt: at, ExpiresAt: at + 120, Mutation: &status}
				shared, err := SignStatement(statement, executorKey())
				if err != nil {
					t.Fatal(err)
				}
				if err = f.m.Report(context.Background(), shared); err != nil {
					t.Fatal(err)
				}
			}
			e = f.m.Approve(context.Background(), f.consent.Binding.DeviceID, f.actor, p.ID, p.Digest, true)
			if state == "idle" {
				if e != nil || f.m.record.Sequence != 1 {
					t.Fatal(e)
				}
			} else if !errors.Is(e, ErrUnavailable) || f.m.record.Sequence != 0 || len(f.m.record.Jobs[0].Envelope) != 0 {
				t.Fatal("unavailable fence consumed approval", e)
			}
		})
	}
}
