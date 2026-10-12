package windowsupdatejob

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/windowsaction"
)

type memoryStore struct {
	files         map[string][]byte
	writes        int
	fail          int
	commitFailure bool
}

func (s *memoryStore) Read(name string) ([]byte, error) {
	b, ok := s.files[name]
	if !ok {
		return nil, ErrIntegrity
	}
	return bytes.Clone(b), nil
}
func (s *memoryStore) Write(name string, b []byte) error {
	s.writes++
	if s.fail == s.writes {
		if s.commitFailure {
			s.files[name] = bytes.Clone(b)
		}
		return ErrUncertain
	}
	s.files[name] = bytes.Clone(b)
	return nil
}
func (s *memoryStore) Verify() error { return nil }

type authorityFixture struct {
	current Current
	calls   int
	before  func(int)
}

func (g *authorityFixture) WithCurrent(ctx context.Context, b Binding, fn func(Current) error) error {
	g.calls++
	if g.before != nil {
		g.before(g.calls)
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return fn(g.current)
}

type readinessFixture struct {
	value Readiness
	calls int
	err   error
}

func (s *readinessFixture) Readiness(context.Context, Binding, Selection) (Readiness, error) {
	s.calls++
	return s.value, s.err
}

type workflowFixture struct {
	m         *Manager
	store     *memoryStore
	guard     *authorityFixture
	source    *readinessFixture
	key       ed25519.PrivateKey
	at        time.Time
	consent   Consent
	id, actor string
}

func fixture(t *testing.T) *workflowFixture {
	t.Helper()
	f := &workflowFixture{at: time.Unix(1800000000, 0).UTC(), id: "update_" + strings.Repeat("4", 32), actor: "operator_" + strings.Repeat("5", 32)}
	f.key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{72}, 32))
	b := Binding{ManagerID: "manager_" + strings.Repeat("1", 32), DeviceID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: actionpermit.Digest([]byte("original")), ExecutorID: "executor_" + strings.Repeat("3", 32), ExecutorKeyID: actionpermit.Digest(executorKey().Public().(ed25519.PublicKey)), GrantID: "grant_" + strings.Repeat("6", 32), KeyID: actionpermit.Digest(f.key.Public().(ed25519.PublicKey))}
	f.consent = Consent{Version: ConsentVersion, Scope: Scope, Binding: b, Enabled: true, Acknowledged: true, ExpiresAt: f.at.Unix() + 3600}
	f.guard = &authorityFixture{current: Current{Binding: b, LeafDigest: actionpermit.Digest([]byte("leaf")), LeafGeneration: 1, LeafNotBefore: f.at.Unix() - 1, LeafNotAfter: f.at.Unix() + 300, Enabled: true}}
	f.source = &readinessFixture{value: Readiness{Selection: Selection{"11111111-2222-3333-4444-555555555555", 3}, CapturedAt: f.at.Unix(), Software: Yes, Installed: No, Hidden: No, Downloaded: Yes, EULAAccepted: Yes, CanRequestUserInput: No, CanRequireSource: No, RequiresNetwork: No, BundledCount: 0, InstallerBusy: No, RebootRequiredBefore: No, RebootBehavior: "can", OfflineVerified: Yes}}
	r, e := NewRecordWithExecutor(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeRecord(r)
	c, _ := json.Marshal(f.consent)
	f.store = &memoryStore{files: map[string][]byte{"jobs.json": raw, "started.json": c, "receipt.json": c}}
	f.m, e = Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *workflowFixture) request(t *testing.T) {
	t.Helper()
	if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e != nil {
		t.Fatal(e)
	}
}
func (f *workflowFixture) approve(t *testing.T) []byte {
	t.Helper()
	f.request(t)
	p := f.m.record.Jobs[len(f.m.record.Jobs)-1].Preview
	if p == nil {
		t.Fatal("missing preview")
	}
	if e := f.m.Approve(context.Background(), f.consent.Binding.DeviceID, f.actor, p.ID, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	return bytes.Clone(f.m.record.Jobs[len(f.m.record.Jobs)-1].Envelope)
}
func TestWorkflowExactApprovalClaimAndResult(t *testing.T) {
	f := fixture(t)
	f.request(t)
	if f.source.calls != 1 {
		t.Fatal("no readiness")
	}
	before := bytes.Clone(f.store.files["jobs.json"])
	f.request(t)
	if f.source.calls != 1 || !bytes.Equal(before, f.store.files["jobs.json"]) {
		t.Fatal("request replay changed original readiness")
	}
	p := *f.m.record.Jobs[0].Preview
	for _, tc := range []struct {
		actor, digest string
		ack           bool
	}{{f.actor, p.Digest, false}, {"operator_" + strings.Repeat("7", 32), p.Digest, true}, {f.actor, actionpermit.Digest([]byte("other")), true}} {
		if e := f.m.Approve(context.Background(), f.consent.Binding.DeviceID, tc.actor, p.ID, tc.digest, tc.ack); e == nil {
			t.Fatal("invalid approval admitted")
		}
	}
	raw := f.approve(t)
	if e := f.m.Approve(context.Background(), f.consent.Binding.DeviceID, f.actor, p.ID, p.Digest, true); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(raw, f.m.record.Jobs[0].Envelope) || f.m.record.Sequence != 1 {
		t.Fatal("approval repeated")
	}
	got, e := f.m.Claim(context.Background(), p.ID)
	if e != nil || !bytes.Equal(got, raw) {
		t.Fatal(e)
	}
	if raw, e = f.m.Claim(context.Background(), p.ID); !errors.Is(e, ErrConsumed) || len(raw) != 0 {
		t.Fatal("claim repeated")
	}
	result := Result{JobID: p.ID, EnvelopeDigest: actionpermit.Digest(got), Attempted: true, Outcome: "succeeded", OperationResult: 2, RebootRequired: Yes, CompletedAt: f.at.Unix()}
	if e = f.m.Submit(context.Background(), result); e != nil {
		t.Fatal(e)
	}
	if e = f.m.Submit(context.Background(), result); e != nil {
		t.Fatal(e)
	}
	result.RebootRequired = No
	if e = f.m.Submit(context.Background(), result); !errors.Is(e, ErrConflict) {
		t.Fatal("result overwritten")
	}
	v, e := f.m.View(context.Background(), f.consent.Binding.DeviceID, f.actor)
	if e != nil || v.Job.Result.Outcome != "succeeded" {
		t.Fatal(e)
	}
	body, _ := json.Marshal(v)
	for _, secret := range []string{"envelope\"", "signature", "publicKey"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("execution material leaked")
		}
	}
}
func TestReadinessNeverPromotesObservationOrUnknown(t *testing.T) {
	cases := map[string]func(*Readiness){"eula": func(r *Readiness) { r.EULAAccepted = No }, "unknown": func(r *Readiness) { r.EULAAccepted = Unknown }, "bundle": func(r *Readiness) { r.BundledCount = 1 }, "missing_bundle": func(r *Readiness) { r.BundledCount = -1 }, "interaction": func(r *Readiness) { r.CanRequestUserInput = Yes }, "source": func(r *Readiness) { r.CanRequireSource = Yes }, "network": func(r *Readiness) { r.RequiresNetwork = Yes }, "busy": func(r *Readiness) { r.InstallerBusy = Yes }, "reboot": func(r *Readiness) { r.RebootRequiredBefore = Yes }, "not_cached": func(r *Readiness) { r.Downloaded = No }, "online": func(r *Readiness) { r.OfflineVerified = No }, "changed_revision": func(r *Readiness) { r.Selection.Revision++ }, "unknown_reboot": func(r *Readiness) { r.RebootBehavior = "unknown" }, "stale": func(r *Readiness) { r.CapturedAt -= 61 }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			selection := f.source.value.Selection
			mutate(&f.source.value)
			if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, selection); e != nil {
				t.Fatal(e)
			}
			if f.m.record.Jobs[0].State != "blocked" {
				t.Fatal("unsafe readiness promoted")
			}
		})
	}
}
func TestCurrentLeafRenewalDoesNotExtendOriginalPreview(t *testing.T) {
	f := fixture(t)
	f.request(t)
	deadline := f.m.record.Jobs[0].Preview.ExpiresAt
	f.guard.current.LeafGeneration++
	f.guard.current.LeafDigest = actionpermit.Digest([]byte("renewed"))
	f.guard.current.LeafNotAfter += 1000
	f.at = f.at.Add(10 * time.Second)
	p := f.m.record.Jobs[len(f.m.record.Jobs)-1].Preview
	if e := f.m.Approve(context.Background(), f.consent.Binding.DeviceID, f.actor, p.ID, p.Digest, true); e != nil {
		t.Fatal("same identity renewal rejected", e)
	}
	if f.m.record.Jobs[0].Preview.ExpiresAt != deadline {
		t.Fatal("deadline extended")
	}
	f.at = time.Unix(deadline, 0).UTC()
	if _, e := f.m.Claim(context.Background(), p.ID); !errors.Is(e, ErrExpired) {
		t.Fatal("expired claim accepted")
	}
}
func TestFreshLocalConsentAndLiveAuthorityFailClosed(t *testing.T) {
	for _, name := range []string{"revoked", "scope_disabled", "leaf_expired", "identity_changed", "clock_rollback"} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			switch name {
			case "revoked":
				f.guard.current.Revoked = true
			case "scope_disabled":
				f.guard.current.Enabled = false
			case "leaf_expired":
				f.guard.current.LeafNotAfter = f.at.Unix()
			case "identity_changed":
				f.guard.current.Binding.IncarnationDigest = actionpermit.Digest([]byte("replacement"))
			case "clock_rollback":
				f.at = f.at.Add(-time.Second)
			}
			if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e == nil || f.source.calls != 0 {
				t.Fatal("authority bypass", e)
			}
		})
	}
	f := fixture(t)
	c := f.consent
	c.Acknowledged = false
	if c.Validate() == nil {
		t.Fatal("unchecked consent accepted")
	}
	c.Enabled = false
	if c.Validate() != nil {
		t.Fatal("default-off consent invalid")
	}
}
func TestStoreUncertaintyAndMissingUsedStateNeverRetry(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "committed_reply_lost"}[commit], func(t *testing.T) {
			f := fixture(t)
			f.store.fail = 1
			f.store.commitFailure = commit
			if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); !errors.Is(e, ErrUncertain) {
				t.Fatal(e)
			}
			if f.source.calls != 0 {
				t.Fatal("source ran before durable request")
			}
			f.store.fail = 0
			if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id, f.source.value.Selection); e == nil {
				t.Fatal("uncertain session retried")
			}
		})
	}
	for _, name := range []string{"started.json", "receipt.json", "jobs.json"} {
		f := fixture(t)
		delete(f.store.files, name)
		if _, e := Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at }); e == nil {
			t.Fatal("missing state adopted", name)
		}
	}
}
func TestReopenPreservesClaimAndApprovalBytes(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	_, e := f.m.Claim(context.Background(), f.id)
	if e != nil {
		t.Fatal(e)
	}
	m, e := Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	if got, e := m.Claim(context.Background(), f.id); !errors.Is(e, ErrConsumed) || len(got) > 0 {
		t.Fatal("redelivered after restart")
	}
	if !bytes.Equal(raw, m.record.Jobs[0].Envelope) {
		t.Fatal("saved envelope changed")
	}
}
func TestUpdateDomainRejectsServiceActionAndCanonicalTampering(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	if _, e := windowsaction.Decode(raw); e == nil {
		t.Fatal("update became service action")
	}
	if _, e := Verify(append(raw, '\n'), f.key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("alternate encoding accepted")
	}
	raw = bytes.Replace(raw, []byte(`"revision":3`), []byte(`"revision":4`), 1)
	if _, e := Verify(raw, f.key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("tampered update accepted")
	}
}

type nativeFixture struct {
	readiness       Readiness
	opens, installs int
	err             error
	onInspect       func()
	onInstall       func()
	result          NativeResult
}

func (n *nativeFixture) PrepareExact(context.Context, Selection) (PreparedUpdate, error) {
	n.opens++
	return n, nil
}
func (n *nativeFixture) Inspect(context.Context) (Readiness, error) {
	if n.onInspect != nil {
		n.onInspect()
	}
	return n.readiness, nil
}
func (n *nativeFixture) InstallOnce(context.Context) (NativeResult, error) {
	n.installs++
	if n.onInstall != nil {
		n.onInstall()
	}
	return n.result, n.err
}
func (n *nativeFixture) Close() error { return nil }
func executorFixture(t *testing.T, f *workflowFixture, n ExecutorAdapter) (*Executor, *memoryStore) {
	t.Helper()
	r, e := NewExecutorRecord(f.consent, f.key.Public().(ed25519.PublicKey), executorKey().Public().(ed25519.PublicKey), f.at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := EncodeExecutorRecord(r)
	c, _ := json.Marshal(f.consent)
	s := &memoryStore{files: map[string][]byte{"executor.json": raw, "started.json": c, "receipt.json": c}}
	x, e := OpenExecutor(s, f.guard, n, executorKey(), func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	return x, s
}
func TestExecutorPersistsAttemptBeforeOneNativeCall(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: Yes}}
	x, s := executorFixture(t, f, n)
	n.onInstall = func() {
		var r ExecutorRecord
		if canonical(s.files["executor.json"], &r, MaxBytes) != nil || !r.Attempts[0].Attempted || r.Attempts[0].Result != nil {
			t.Fatal("attempt not durable before call")
		}
	}
	r, e := x.Execute(context.Background(), raw)
	if e != nil || r.Outcome != "succeeded" || !r.Attempted || n.installs != 1 {
		t.Fatal(r, e)
	}
	if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("native retry")
	}
	x, e = OpenExecutor(s, f.guard, n, executorKey(), func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("restart repeated native")
	}
}
func TestExecutorFinalRevocationAndRevisionRecheck(t *testing.T) {
	for _, name := range []string{"revoke", "expiry", "revision", "eula"} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			raw := f.approve(t)
			n := &nativeFixture{readiness: f.source.value}
			switch name {
			case "revoke":
				n.onInspect = func() { f.guard.current.Revoked = true }
			case "expiry":
				n.onInspect = func() { f.at = f.at.Add(time.Minute) }
			case "revision":
				n.readiness.Selection.Revision++
			case "eula":
				n.readiness.EULAAccepted = No
			}
			x, _ := executorFixture(t, f, n)
			r, e := x.Execute(context.Background(), raw)
			if e != nil || r.Outcome != "not_attempted" || r.Attempted || n.installs != 0 {
				t.Fatal("final guard bypass", r, e)
			}
		})
	}
}
func TestExecutorUncertaintyAndCrashNeverRetry(t *testing.T) {
	for _, fail := range []int{1, 2, 3} {
		f := fixture(t)
		raw := f.approve(t)
		n := &nativeFixture{readiness: f.source.value, result: NativeResult{OperationResult: 2, RebootRequired: No}}
		x, s := executorFixture(t, f, n)
		s.fail = fail
		s.commitFailure = true
		if _, e := x.Execute(context.Background(), raw); !errors.Is(e, ErrUncertain) {
			t.Fatal(fail, e)
		}
		before := n.installs
		s.fail = 0
		x, e := OpenExecutor(s, f.guard, n, executorKey(), func() time.Time { return f.at })
		if e != nil {
			t.Fatal(e)
		}
		if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != before {
			t.Fatal("replayed uncertain attempt")
		}
	}
	f := fixture(t)
	raw := f.approve(t)
	n := &nativeFixture{readiness: f.source.value, err: context.DeadlineExceeded}
	x, _ := executorFixture(t, f, n)
	r, e := x.Execute(context.Background(), raw)
	if e != nil || r.Outcome != "uncertain" {
		t.Fatal(r, e)
	}
	if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrConsumed) || n.installs != 1 {
		t.Fatal("timeout retried")
	}
}
func TestInactiveAdapterCannotInstall(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	x, _ := executorFixture(t, f, InactiveExecutor{})
	r, e := x.Execute(context.Background(), raw)
	if e != nil || r.Attempted || r.Outcome != "not_attempted" {
		t.Fatal(r, e)
	}
}

func TestRejectedExpiryFloorSurvivesRestart(t *testing.T) {
	f := fixture(t)
	raw := f.approve(t)
	x, s := executorFixture(t, f, InactiveExecutor{})
	f.at = f.at.Add(61 * time.Second)
	if _, e := f.m.Claim(context.Background(), f.id); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	if _, e := x.Execute(context.Background(), raw); !errors.Is(e, ErrExpired) {
		t.Fatal(e)
	}
	f.at = f.at.Add(-31 * time.Second)
	m, e := Open(f.store, f.guard, f.source, f.key, func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Claim(context.Background(), f.id); !errors.Is(e, ErrExpired) {
		t.Fatal("expired manager job revived", e)
	}
	x, e = OpenExecutor(s, f.guard, InactiveExecutor{}, executorKey(), func() time.Time { return f.at })
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x.Execute(context.Background(), raw); !errors.Is(e, ErrExpired) {
		t.Fatal("expired executor job revived", e)
	}
}
func TestOnlyOneLivePreviewAndUnsignedChecksDoNotConsumeCapacity(t *testing.T) {
	f := fixture(t)
	f.request(t)
	next := "update_" + strings.Repeat("8", 32)
	if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, next, f.source.value.Selection); !errors.Is(e, ErrConflict) {
		t.Fatal("second live preview admitted", e)
	}
	f.approve(t)
	f = fixture(t)
	f.source.err = ErrUnavailable
	for i := 0; i < MaxJobs+4; i++ {
		id := fmt.Sprintf("update_%032x", i+1)
		if e := f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, id, f.source.value.Selection); e != nil {
			t.Fatal(e)
		}
	}
	v, e := f.m.View(context.Background(), f.consent.Binding.DeviceID, f.actor)
	if e != nil || !v.Available || f.m.record.Sequence != 0 || len(f.m.record.Jobs) != 1 {
		t.Fatal(v, e, "readiness consumed permanent capacity")
	}
}
func TestApprovedCapacityRetainsEveryEnvelope(t *testing.T) {
	f := fixture(t)
	f.guard.current.LeafNotAfter = f.at.Unix() + 3600
	for i := 0; i < MaxJobs; i++ {
		f.id = fmt.Sprintf("update_%032x", i+1)
		f.source.value.CapturedAt = f.at.Unix()
		f.approve(t)
		f.at = f.at.Add(time.Minute)
	}
	v, e := f.m.View(context.Background(), f.consent.Binding.DeviceID, f.actor)
	if e != nil || v.Available || v.Reason != "capacity_exhausted" || len(f.m.record.Jobs) != MaxJobs {
		t.Fatal(v, e)
	}
	if e = f.m.Request(context.Background(), f.consent.Binding.DeviceID, f.actor, "update_"+strings.Repeat("f", 32), f.source.value.Selection); !errors.Is(e, ErrConflict) {
		t.Fatal("capacity exceeded")
	}
}
func TestSourceErrorCannotReturnUsableReadiness(t *testing.T) {
	f := fixture(t)
	f.source.err = ErrUnavailable
	f.request(t)
	if f.m.record.Jobs[0].State != "blocked" {
		t.Fatal("errored source accepted")
	}
}

func executorKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32)) }

func TestSignedExecutorReadinessAndResultRelay(t *testing.T) {
	f := fixture(t)
	f.m.source = nil
	f.request(t)
	pending, e := f.m.Pending(context.Background())
	if e != nil || pending.Kind != "readiness" {
		t.Fatal(pending, e)
	}
	raw, e := f.m.ClaimReadiness(context.Background(), f.id)
	if e != nil {
		t.Fatal(e)
	}
	challenge, e := VerifyChallenge(raw, f.key.Public().(ed25519.PublicKey))
	if e != nil || challenge.Selection != f.source.value.Selection {
		t.Fatal(e)
	}
	if got, e := f.m.ClaimReadiness(context.Background(), f.id); !errors.Is(e, ErrConsumed) || len(got) > 0 {
		t.Fatal("readiness redelivered")
	}
	statement := Statement{Version: RelayVersion, Kind: "readiness", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: actionpermit.Digest(raw), Deadline: challenge.Deadline, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Readiness: &f.source.value}
	signed, e := SignStatement(statement, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.m.Report(context.Background(), signed); e != nil {
		t.Fatal(e)
	}
	if e = f.m.Report(context.Background(), signed); e != nil {
		t.Fatal("identical report rejected", e)
	}
	if e = f.m.Review(context.Background(), f.consent.Binding.DeviceID, f.actor, f.id); e != nil {
		t.Fatal(e)
	}
	permit := f.approve(t)
	pending, e = f.m.Pending(context.Background())
	if e != nil || pending.Kind != "install" {
		t.Fatal(pending, e)
	}
	claimed, e := f.m.Claim(context.Background(), f.id)
	if e != nil || !bytes.Equal(permit, claimed) {
		t.Fatal(e)
	}
	result := Result{JobID: f.id, EnvelopeDigest: actionpermit.Digest(permit), Attempted: true, Outcome: "succeeded", OperationResult: 2, RebootRequired: No, CompletedAt: f.at.Unix()}
	p, _ := Verify(permit, f.key.Public().(ed25519.PublicKey))
	statement = Statement{Version: RelayVersion, Kind: "result", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: result.EnvelopeDigest, Deadline: p.Preview.ExpiresAt, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 300, Result: &result}
	signed, e = SignStatement(statement, executorKey())
	if e != nil {
		t.Fatal(e)
	}
	if e = f.m.Report(context.Background(), signed); e != nil {
		t.Fatal(e)
	}
	f.at = f.at.Add(301 * time.Second)
	f.guard.current.LeafNotAfter += 600
	if e = f.m.Report(context.Background(), signed); e != nil {
		t.Fatal("identical saved result must not re-execute or re-age", e)
	}
}
func TestExecutorProofCannotBeForgedByObserverOrOtherRequest(t *testing.T) {
	for _, kind := range []string{"wrong_key", "other_request", "other_revision", "expired", "unknown_field", "unsigned"} {
		t.Run(kind, func(t *testing.T) {
			f := fixture(t)
			f.m.source = nil
			f.request(t)
			challengeRaw, e := f.m.ClaimReadiness(context.Background(), f.id)
			if e != nil {
				t.Fatal(e)
			}
			c, _ := VerifyChallenge(challengeRaw, f.key.Public().(ed25519.PublicKey))
			r := f.source.value
			s := Statement{Version: RelayVersion, Kind: "readiness", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: actionpermit.Digest(challengeRaw), Deadline: c.Deadline, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Readiness: &r}
			switch kind {
			case "other_request":
				s.ReferenceDigest = actionpermit.Digest([]byte("other"))
			case "other_revision":
				r.Selection.Revision++
			case "expired":
				f.at = f.at.Add(60 * time.Second)
			}
			signed, e := SignStatement(s, executorKey())
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "wrong_key":
				var env statementEnvelope
				_ = json.Unmarshal(signed, &env)
				env.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, statementMessage(s)))
				signed, _ = json.Marshal(env)
			case "unknown_field":
				signed = append(signed[:len(signed)-1], []byte(`,"extra":true}`)...)
			case "unsigned":
				signed, _ = json.Marshal(s)
			}
			if e = f.m.Report(context.Background(), signed); e == nil {
				t.Fatal("forged report admitted")
			}
			if f.m.record.Jobs[0].Preview != nil {
				t.Fatal("forged preview retained")
			}
		})
	}
}

func TestCompleteSignedHistoryFitsCapacity(t *testing.T) {
	f := fixture(t)
	f.m.source = nil
	for i := 0; i < MaxJobs; i++ {
		f.id = fmt.Sprintf("update_%032x", i+1)
		f.request(t)
		challenge, e := f.m.ClaimReadiness(context.Background(), f.id)
		if e != nil {
			t.Fatal(e)
		}
		c, _ := VerifyChallenge(challenge, f.key.Public().(ed25519.PublicKey))
		proof, e := SignStatement(Statement{Version: RelayVersion, Kind: "readiness", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: actionpermit.Digest(challenge), Deadline: c.Deadline, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 60, Readiness: &f.source.value}, executorKey())
		if e != nil {
			t.Fatal(e)
		}
		if e = f.m.Report(context.Background(), proof); e != nil {
			t.Fatal(i, e)
		}
		f.approve(t)
		permit, e := f.m.Claim(context.Background(), f.id)
		if e != nil {
			t.Fatal(i, e)
		}
		p, _ := Verify(permit, f.key.Public().(ed25519.PublicKey))
		result := Result{JobID: f.id, EnvelopeDigest: actionpermit.Digest(permit), Attempted: true, Outcome: "succeeded", OperationResult: 2, RebootRequired: No, CompletedAt: f.at.Unix()}
		proof, e = SignStatement(Statement{Version: RelayVersion, Kind: "result", Binding: f.consent.Binding, JobID: f.id, ReferenceDigest: result.EnvelopeDigest, Deadline: p.Preview.ExpiresAt, IssuedAt: f.at.Unix(), ExpiresAt: f.at.Unix() + 300, Result: &result}, executorKey())
		if e != nil {
			t.Fatal(e)
		}
		if e = f.m.Report(context.Background(), proof); e != nil {
			t.Fatal(i, e)
		}
	}
	if len(f.m.record.Jobs) != MaxJobs || len(f.m.raw) > MaxBytes {
		t.Fatal("approved history capacity differs from advertised bound")
	}
	old := f.m.record.Jobs[0]
	view, e := f.m.View(context.Background(), f.consent.Binding.DeviceID, f.actor, old.ID)
	if e != nil || view.Job.ID != old.ID || view.Job.Result == nil {
		t.Fatal("exact old job status unavailable", e)
	}
}
