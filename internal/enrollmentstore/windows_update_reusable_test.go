package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	job "localrmm/internal/windowsupdatejob"
	"testing"
	"time"
)

// Real enrollment SQLite commits/reopens supplement the inert 40-job native
// adapter handshake. These signatures are fixtures, never native acceptance.
func TestReusableWUAEnrollmentRetirementCommitsAndReopens(t *testing.T) {
	f := newWindowsSoftwareStoreFixture(t, false)
	ctx := context.Background()
	wk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{117}, 32))
	we := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{118}, 32))
	g := managedStoreGrant(f)
	g.Version = msi.ReusableGrantVersion
	g.ReusableAcknowledged = true
	g.MutationPlanDigest = msi.Digest([]byte("fresh reusable WUA pair"))
	c := job.Consent{Version: job.ReusableConsentVersion, ReusableAcknowledged: true, BackgroundAcknowledged: true, Scope: job.Scope, Binding: job.Binding{ManagerID: g.Binding.ManagerID, DeviceID: g.Binding.DeviceID, IncarnationDigest: g.Binding.IncarnationDigest, KeyID: msi.Digest(wk.Public().(ed25519.PublicKey)), ExecutorKeyID: msi.Digest(we.Public().(ed25519.PublicKey)), ExecutorID: id("executor", 8), GrantID: id("grant", 9)}, Enabled: true, Acknowledged: true, ExpiresAt: g.ExpiresAt, MutationPlanDigest: g.MutationPlanDigest}
	b, _ := json.Marshal(c.Binding)
	g.PeerBindingDigest = msi.Digest(b)
	b, _ = json.Marshal(g.Binding)
	c.PeerBindingDigest = msi.Digest(b)
	if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, f.key.Public().(ed25519.PublicKey), f.executor.Public().(ed25519.PublicKey), g, f.at, false); e != nil {
		t.Fatal(e)
	}
	if e := f.store.SetupWindowsUpdateJobsCreateOnly(ctx, wk.Public().(ed25519.PublicKey), we.Public().(ed25519.PublicKey), c, f.at); e != nil {
		t.Fatal(e)
	}
	actor := id("operator", 9)
	selection := job.Selection{UpdateID: "12345678-1234-1234-1234-123456789abc", Revision: 2}
	var priorAck []byte
	for i := 1; i <= 3; i++ {
		m, e := job.OpenTransactional(ctx, f.store, c.Binding, wk, func() time.Time { return f.at })
		if e != nil {
			t.Fatal(i, e)
		}
		if e = m.ConfigureOperatorPolicy(func(a string) bool { return a == actor }); e != nil {
			t.Fatal(e)
		}
		jid := id("update", i)
		if e = m.Request(ctx, c.Binding.DeviceID, actor, jid, selection); e != nil {
			t.Fatal("request", i, e)
		}
		if len(priorAck) > 0 {
			if e = m.Report(ctx, priorAck); e != nil {
				t.Fatal("prior exact ack starved next request", e)
			}
		}
		challenge, e := m.ClaimReadiness(ctx, jid)
		if e != nil {
			t.Fatal(e)
		}
		ch, _ := job.VerifyChallenge(challenge, wk.Public().(ed25519.PublicKey))
		r := job.Readiness{Selection: selection, CapturedAt: f.at.Unix(), Software: job.Yes, Installed: job.No, Hidden: job.No, Downloaded: job.Yes, EULAAccepted: job.Yes, CanRequestUserInput: job.No, CanRequireSource: job.No, RequiresNetwork: job.No, BundledCount: 0, InstallerBusy: job.No, RebootRequiredBefore: job.No, RebootBehavior: "never", OfflineVerified: job.Yes}
		proof, e := job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "readiness", Binding: c.Binding, JobID: jid, ReferenceDigest: actionpermit.Digest(challenge), Deadline: ch.Deadline, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Readiness: &r}, we)
		if e != nil {
			t.Fatal(e)
		}
		if e = m.Report(ctx, proof); e != nil {
			t.Fatal("readiness", e)
		}
		status := fence.Status{Active: true, Phase: "idle", Revision: uint64(i), Retained: 1}
		shared, _ := job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "mutation", Binding: c.Binding, JobID: jid, ReferenceDigest: actionpermit.Digest(challenge), Deadline: ch.Deadline, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Mutation: &status}, we)
		if e = m.Report(ctx, shared); e != nil {
			t.Fatal("shared", e)
		}
		view, e := m.View(ctx, c.Binding.DeviceID, actor)
		if e != nil || view.Job == nil || view.Job.Preview == nil {
			t.Fatal(e)
		}
		if e = m.Approve(ctx, c.Binding.DeviceID, actor, jid, view.Job.Preview.Digest, true); e != nil {
			t.Fatal("approve", e)
		}
		permit, e := m.Claim(ctx, jid)
		if e != nil {
			t.Fatal(e)
		}
		p, _ := job.Verify(permit, wk.Public().(ed25519.PublicKey))
		result := job.Result{JobID: jid, EnvelopeDigest: actionpermit.Digest(permit), Attempted: true, Outcome: "succeeded", OperationResult: 2, RebootRequired: job.No, CompletedAt: f.at.Unix()}
		proof, _ = job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "result", Binding: c.Binding, JobID: jid, ReferenceDigest: result.EnvelopeDigest, Deadline: p.Preview.ExpiresAt, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 300, Result: &result}, we)
		if e = m.Report(ctx, proof); e != nil {
			t.Fatal("result", e)
		}
		if e = m.Retire(ctx, c.Binding.DeviceID, actor, jid, uint64(i), result.EnvelopeDigest, actionpermit.Digest(proof), true); e != nil {
			t.Fatal("retire", e)
		}
		retire, e := m.ClaimRetirement(ctx, jid)
		if e != nil {
			t.Fatal("retirement claim", e)
		}
		q, _ := job.VerifyRetirement(retire, wk.Public().(ed25519.PublicKey))

		if i == 1 {
			allowed := true
			replay, e := job.OpenTransactional(ctx, f.store, c.Binding, wk, func() time.Time { return f.at })
			if e != nil {
				t.Fatal(e)
			}
			if e = replay.ConfigureOperatorPolicy(func(a string) bool { return a == actor && allowed }); e != nil {
				t.Fatal(e)
			}
			calls := 0
			raceCtx := WithOverviewClock(ctx, func() time.Time {
				calls++
				if calls >= 2 {
					allowed = false
				}
				return f.at
			})
			if raw, e := replay.ClaimRetirement(raceCtx, jid); !errors.Is(e, job.ErrAuthority) || len(raw) != 0 {
				t.Fatal("replay bypassed final actor", e)
			}
		}
		if i == 3 {
			expired := time.Unix(q.ExpiresAt, 0)
			calls := 0
			raceCtx := WithOverviewClock(ctx, func() time.Time {
				calls++
				if calls >= 2 {
					return expired
				}
				return f.at
			})
			if raw, e := m.ClaimRetirement(raceCtx, jid); !errors.Is(e, job.ErrExpired) || len(raw) != 0 {
				t.Fatal("replay escaped final expiry", e)
			}
			if e = f.store.Close(); e != nil {
				t.Fatal(e)
			}
			f.store, e = Open(f.path, f.fixture.config, f.fixture.issuerDER)
			if e != nil {
				t.Fatal("expired rejection reopen", e)
			}
			defer f.store.Close()
			saved, e := f.store.ReadRegisteredWindowsUpdateJob(ctx, c.Binding, wk.Public().(ed25519.PublicKey))
			if e != nil || saved.RetiredFloor != 2 || len(saved.Jobs[0].RetireReport) != 0 || !bytes.Equal(saved.Jobs[0].RetirePermit, retire) {
				t.Fatal("expiry changed evidence", e)
			}
			return
		}
		priorAck, e = job.SignRetirementReport(job.RetirementReport{Version: job.RetirementVersion, Binding: c.Binding, JobID: jid, Selection: selection, Occurrence: uint64(i), ReferenceDigest: actionpermit.Digest(retire), EnvelopeDigest: result.EnvelopeDigest, ResultDigest: actionpermit.Digest(proof), ReleaseDigest: actionpermit.Digest([]byte("synthetic released receipt")), IssuedAt: f.at.Unix(), ExpiresAt: q.ExpiresAt}, we)
		if e != nil {
			t.Fatal(e)
		}
		if e = m.Report(ctx, priorAck); e != nil {
			t.Fatal("retirement ack", e)
		}
		before, e := f.store.ReadRegisteredWindowsUpdateJob(ctx, c.Binding, wk.Public().(ed25519.PublicKey))
		if e != nil || before.RetiredFloor != uint64(i) {
			t.Fatal("saved floor", e)
		}
		_, _, e = f.store.WindowsUpdateJobTransaction(ctx, c.Binding, wk.Public().(ed25519.PublicKey), f.at, func(r *job.Record, _ job.Current, _ time.Time) error { r.Jobs = nil; r.RetiredFloor = 0; return nil })
		if e == nil {
			t.Fatal("callback erased replay evidence")
		}
		if e = f.store.Close(); e != nil {
			t.Fatal(e)
		}
		f.store, e = Open(f.path, f.fixture.config, f.fixture.issuerDER)
		if e != nil {
			t.Fatal("reopen", e)
		}
		f.at = f.at.Add(time.Second)
	}
	defer f.store.Close()
}
