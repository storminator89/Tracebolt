//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstore"
	msi "localrmm/internal/windowsmanagedmsi"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"net/http"
	"strings"
	"testing"
	"time"
)

// This inert IPC peer saves one readiness report per consumed challenge. It
// exercises the real sender plus enrollment-owned manager; native-edge behavior
// is covered by the independent shared-fence domain integration fixtures.
type scheduledSavedPeer struct {
	now                func() time.Time
	key                ed25519.PrivateKey
	binding            job.Binding
	ready              job.Readiness
	challenge, report  []byte
	shared             fence.Status
	readiness, submits int
}

func (p *scheduledSavedPeer) CheckPeer(context.Context, job.Binding) error { return nil }
func (p *scheduledSavedPeer) Readiness(_ context.Context, raw []byte) ([]byte, error) {
	var envelope struct {
		Challenge job.Challenge `json:"challenge"`
		Signature string        `json:"signature"`
	}
	if json.Unmarshal(raw, &envelope) != nil {
		return nil, job.ErrInvalid
	}
	c := envelope.Challenge
	if bytes.Equal(raw, p.challenge) {
		return nil, job.ErrConsumed
	}
	p.readiness++
	p.challenge = bytes.Clone(raw)
	r := p.ready
	r.CapturedAt = p.now().Unix()
	proof, e := job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "readiness", Binding: p.binding, JobID: c.JobID, ReferenceDigest: actionpermit.Digest(raw), Deadline: c.Deadline, IssuedAt: r.CapturedAt, ExpiresAt: min(r.CapturedAt+60, c.Deadline), Readiness: &r}, p.key)
	p.report = bytes.Clone(proof)
	return proof, e
}
func (p *scheduledSavedPeer) Submit(context.Context, []byte) error { p.submits++; return nil }
func (p *scheduledSavedPeer) Status(context.Context) (job.ExecutorStatus, error) {
	out := job.ExecutorStatus{ObservedAt: p.now().Unix(), InstallCapacityRemaining: 32, Attempts: []job.EvidenceStatus{}}
	if len(p.challenge) == 0 {
		return out, nil
	}
	var envelope struct {
		Challenge job.Challenge `json:"challenge"`
		Signature string        `json:"signature"`
	}
	if json.Unmarshal(p.challenge, &envelope) != nil {
		return out, job.ErrInvalid
	}
	c := envelope.Challenge
	report, e := job.VerifyStatement(p.report, p.key.Public().(ed25519.PublicKey))
	if e != nil {
		return out, e
	}
	state := "available"
	if p.now().Unix() >= report.ExpiresAt {
		state = "expired"
	}
	out.ReadinessSequence = c.Sequence
	out.Readiness = &job.EvidenceStatus{Kind: "readiness", JobID: c.JobID, ReferenceDigest: actionpermit.Digest(p.challenge), Selection: c.Selection, Sequence: c.Sequence, Deadline: c.Deadline, ClaimedAt: report.IssuedAt, ReportState: state, ReportIssuedAt: report.IssuedAt, ReportExpiresAt: report.ExpiresAt}
	out.MutationReport, e = job.SignStatement(job.Statement{Version: job.RelayVersion, Kind: "mutation", Binding: p.binding, JobID: c.JobID, ReferenceDigest: actionpermit.Digest(p.challenge), Deadline: c.Deadline, IssuedAt: p.now().Unix(), ExpiresAt: p.now().Unix() + 60, Mutation: &p.shared}, p.key)
	return out, e
}
func (p *scheduledSavedPeer) Outbox(_ context.Context, kind, id, digest string) ([]byte, error) {
	if kind != "readiness" || digest != actionpermit.Digest(p.challenge) {
		return nil, job.ErrUnavailable
	}
	return bytes.Clone(p.report), nil
}

func TestScheduledBackgroundRelayRefreshesSharedStatusBeforeExactReadinessReconciliation(t *testing.T) {
	f := newWindowsManagerFixtureForTransport(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows", "tls")
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return at }
	mk := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{211}, 32))
	ek := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{212}, 32))
	mp := mk.Public().(ed25519.PublicKey)
	ep := ek.Public().(ed25519.PublicKey)
	id := func(prefix string, c string) string { return prefix + strings.Repeat(c, 32) }
	b := job.Binding{ManagerID: f.config.Binding.InstanceID, DeviceID: f.material.config.AgentID, IncarnationDigest: "sha256:" + journalLeaf(f.material), ExecutorID: id("executor_", "7"), ExecutorKeyID: actionpermit.Digest(ep), GrantID: id("grant_", "6"), KeyID: actionpermit.Digest(mp)}
	mm := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{213}, 32)).Public().(ed25519.PublicKey)
	me := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{214}, 32)).Public().(ed25519.PublicKey)
	mb := msi.Binding{ManagerID: b.ManagerID, DeviceID: b.DeviceID, IncarnationDigest: b.IncarnationDigest, ExecutorID: id("executor_", "4"), ExecutorKeyID: actionpermit.Digest(me), KeyID: actionpermit.Digest(mm), DeliveryGrantID: id("grant_", "4"), InstallGrantID: id("grant_", "5")}
	wb, _ := json.Marshal(b)
	mraw, _ := json.Marshal(mb)
	plan := actionpermit.Digest([]byte("fresh combined relay fixture"))
	grant := msi.Grant{Version: msi.ReusableGrantVersion, ReusableAcknowledged: true, MutationPlanDigest: plan, PeerBindingDigest: actionpermit.Digest(wb), Binding: mb, DeliveryEnabled: true, InstallEnabled: true, DeliveryAcknowledged: true, InstallAcknowledged: true, ServiceRiskAcknowledged: true, ExpiresAt: at.Unix() + 3600}
	if e := f.store.SetupWindowsManagedMSIFleetCreateOnly(ctx, mm, me, grant, at, false); e != nil {
		t.Fatal(e)
	}
	consent := job.Consent{Version: job.ScheduledBackgroundConsentVersion, BackgroundAcknowledged: true, ScheduleScope: job.ScheduleScope, ScheduleAcknowledged: true, MutationPlanDigest: plan, PeerBindingDigest: actionpermit.Digest(mraw), Scope: job.Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: grant.ExpiresAt}
	if e := f.store.SetupWindowsUpdateJobsCreateOnly(ctx, mp, ep, consent, at); e != nil {
		t.Fatal(e)
	}
	manager, e := job.OpenTransactional(ctx, f.store, b, mk, clock)
	if e != nil {
		t.Fatal(e)
	}
	defer manager.Close()
	actor, jobID := id("operator_", "9"), id("update_", "8")
	if e = manager.ConfigureOperatorPolicy(func(a string) bool { return a == actor }); e != nil {
		t.Fatal(e)
	}
	if e = manager.ConfigureSchedulePolicy(ctx, func(a string) bool { return a == actor }); e != nil {
		t.Fatal(e)
	}
	peer := &scheduledSavedPeer{now: clock, key: ek, binding: b, shared: fence.Status{Active: true, Phase: "idle", Revision: 1, Retained: 1}, ready: job.Readiness{Selection: job.Selection{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 3}, CapturedAt: at.Unix(), Software: job.Yes, Installed: job.No, Hidden: job.No, Downloaded: job.Yes, EULAAccepted: job.Yes, CanRequestUserInput: job.No, CanRequireSource: job.No, RequiresNetwork: job.No, BundledCount: 0, InstallerBusy: job.No, RebootRequiredBefore: job.No, RebootBehavior: "can", OfflineVerified: job.Yes}}
	g := WindowsUpdateRelayGrant{Version: WindowsBackgroundUpdateRelayGrantVersion, Scope: WindowsUpdateRelayScope, Enabled: true, Acknowledged: true, SenderBinding: f.material.binding, ManagerOrigin: f.material.config.ManagerOrigin, Binding: b, ManagerPublicKey: mp, ExecutorPublicKey: ep, ExpiresAt: consent.ExpiresAt, ExecutorPeer: windowsupdateipc.PeerConfig{Version: windowsupdateipc.ServicePeerVersion, Binding: b, ExecutorPublicKey: ep, Executable: `C:\Program Files\Tracebolt\tracebolt-windows-update-service.exe`, ExecutableDigest: actionpermit.Digest([]byte("service image")), ConfigurationDigest: actionpermit.Digest([]byte("v5 exact config"))}}
	sender := openWindowsUpdateJobSender(f.material)
	defer sender.Close()
	sender.current = func(Material) bool { return true }
	sender.local = func(Material) (WindowsUpdateRelayGrant, error) { return g, nil }
	sender.now = clock
	sender.newExecutor = nil
	sender.executor = peer
	var reports [][]byte
	claims := 0
	sender.exchange = func(c context.Context, path string, raw []byte) ([]byte, int, error) {
		c = enrollmentstore.WithOverviewClock(c, clock)
		var value any
		var e error
		switch strings.TrimPrefix(path, windowsUpdateJobsRelayPrefix) {
		case "poll":
			value, e = manager.Pending(c)
		case "readiness-claim":
			claims++
			value, e = manager.ClaimReadiness(c, jobID)
		case "install-claim":
			claims++
			value, e = manager.Claim(c, jobID)
		case "report":
			reports = append(reports, bytes.Clone(raw))
			e = manager.Report(c, raw)
			value = struct{}{}
		}
		if e != nil {
			return nil, http.StatusConflict, nil
		}
		if b, ok := value.([]byte); ok {
			return b, http.StatusOK, nil
		}
		b, _ := json.Marshal(value)
		return b, http.StatusOK, nil
	}
	if e = manager.Request(ctx, b.DeviceID, actor, jobID, peer.ready.Selection); e != nil {
		t.Fatal(e)
	}
	if got := sender.Run(ctx); got != "reported" {
		t.Fatal(got)
	}
	v, e := manager.View(ctx, b.DeviceID, actor)
	if e != nil || v.Job.Preview == nil {
		t.Fatal(e)
	}
	start, end := at.Unix()+2, at.Unix()+122
	if e = manager.Schedule(ctx, b.DeviceID, actor, jobID, v.Job.Preview.Digest, start, end, true); e != nil {
		t.Fatal(e)
	}
	at = time.Unix(start, 0)
	peer.shared = fence.Status{Active: true, Blocked: true, Domain: fence.ManagedMSI, JobID: id("transfer_", "2"), Phase: "dispatch_intent", Recovery: "intervention_required", Revision: 2, Retained: 1}
	if got := sender.Run(ctx); got != "outcome_unknown" {
		t.Fatal("busy issuance", got)
	}
	saved := bytes.Clone(peer.report)
	r, e := f.store.ReadRegisteredWindowsUpdateJob(ctx, b, mp)
	if e != nil || r.Sequence != 0 || r.Jobs[0].State != "requested" || claims != 2 || peer.readiness != 2 || peer.submits != 0 {
		t.Fatal("busy changed intent or replayed source", r, e)
	}
	approval := r.Jobs[0].Schedule.Approval
	challenge := bytes.Clone(r.Jobs[0].Challenge)
	at = at.Add(time.Second)
	peer.shared = fence.Status{Active: true, Phase: "idle", Revision: 3, Retained: 1}
	before := len(reports)
	if got := sender.Run(ctx); got != "outcome_unknown" {
		t.Fatal("inert submission has no result", got)
	}
	r, e = f.store.ReadRegisteredWindowsUpdateJob(ctx, b, mp)
	if e != nil || r.Sequence != 1 || r.Jobs[0].State != "claimed" || r.Jobs[0].Schedule.Approval != approval || !bytes.Equal(challenge, r.Jobs[0].Challenge) || peer.readiness != 2 || peer.submits != 1 || claims != 3 {
		t.Fatal("reconciled more than once", r, e)
	}
	if len(reports) < before+2 {
		t.Fatal("missing ordered reconciliation")
	}
	first, e := job.VerifyStatement(reports[before], ep)
	if e != nil || first.Kind != "mutation" || !bytes.Equal(reports[before+1], saved) {
		t.Fatal("shared status did not precede identical saved readiness")
	}
	if _, e = manager.Claim(ctx, jobID); !errors.Is(e, job.ErrConsumed) {
		t.Fatal("repeat delivery", e)
	}
}
