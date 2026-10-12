package windowsmutationfence_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	fence "localrmm/internal/windowsmutationfence"
	wua "localrmm/internal/windowsupdatejob"
)

func reusableWUAPermit(t *testing.T, f *pairedDomains, n uint64) []byte {
	t.Helper()
	p, e := wua.Verify(f.wuaPermit, public(f.wuaKey))
	if e != nil {
		t.Fatal(e)
	}
	p.Version = wua.ReusablePermitVersion
	p.Sequence = n
	p.Preview.ID = id("update_", int(n)+1000)
	p.Preview.Readiness.CapturedAt = f.now().Unix()
	p.Preview.Readiness.Selection.Revision = uint32(n)
	f.wuaNative.readiness = p.Preview.Readiness
	p.Preview.CreatedAt = f.now().Unix()
	p.Preview.ExpiresAt = p.Preview.CreatedAt + 60
	p.Preview.Digest = ""
	b, _ := json.Marshal(p.Preview)
	p.Preview.Digest = actionpermit.Digest(append([]byte("Tracebolt selected WUA preview v1\x00"), b...))
	p.ApprovedAt = p.Preview.CreatedAt
	b, e = wua.Sign(p, f.wuaKey)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func reusableWUARetirement(t *testing.T, f *pairedDomains) []byte {
	t.Helper()
	r := readWUA(t, f.wuaStore)
	if len(r.Attempts) != 1 {
		t.Fatal("one exact current job required")
	}
	a := r.Attempts[0]
	p, e := wua.Verify(a.Envelope, public(f.wuaKey))
	if e != nil {
		t.Fatal(e)
	}
	q := wua.RetirementPermit{Version: wua.RetirementVersion, Binding: f.consent.Binding, JobID: p.Preview.ID, Selection: p.Preview.Readiness.Selection, Occurrence: p.Sequence, EnvelopeDigest: actionpermit.Digest(a.Envelope), ResultDigest: actionpermit.Digest(a.ResultReport), ActorID: id("operator_", 10), IssuedAt: f.now().Unix(), ExpiresAt: f.now().Unix() + 120}
	raw, e := wua.SignRetirement(q, f.wuaKey)
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func restartReusableWUA(t *testing.T, f *pairedDomains) {
	t.Helper()
	f.executor.Close()
	f.wuaSession.Close()
	f.wuaSession = f.shared.Session(t, fence.CachedWUA)
	f.openWUA(t)
}
func TestReusableWUAFortyExactJobsRetireAndReopen(t *testing.T) {
	f := newPair(t, true, true, false, false, true)
	ctx := context.Background()
	originalConsent, _ := json.Marshal(f.consent)
	var firstPermit, firstChallenge, firstRetirement []byte
	for n := uint64(1); n <= 40; n++ {
		raw := reusableWUAPermit(t, f, n)
		p, _ := wua.Verify(raw, public(f.wuaKey))
		challenge, e := wua.SignChallenge(wua.Challenge{Version: wua.RelayVersion, Binding: f.consent.Binding, JobID: p.Preview.ID, Selection: p.Preview.Readiness.Selection, IssuedAt: f.now().Unix(), Sequence: n, Deadline: f.now().Unix() + 120}, f.wuaKey)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.executor.Readiness(ctx, challenge); e != nil {
			t.Fatal("readiness", n, e)
		}
		result, e := f.executor.Execute(ctx, raw)
		if e != nil || result.Outcome != "succeeded" || !result.Attempted {
			t.Fatal("execute", n, result, e)
		}
		if _, e = f.executor.Accept(ctx, reusableWUAPermit(t, f, n+1)); !errors.Is(e, wua.ErrConflict) {
			t.Fatal("unretired result admitted replacement", e)
		}
		retirement := reusableWUARetirement(t, f)
		ack, e := f.executor.Retire(ctx, retirement)
		if e != nil {
			t.Fatal("retire", n, e)
		}
		saved, e := f.executor.Retire(ctx, retirement)
		if e != nil || !bytes.Equal(ack, saved) {
			t.Fatal("exact retirement replay changed ack", e)
		}
		if n == 1 {
			firstPermit, firstChallenge, firstRetirement = bytes.Clone(raw), bytes.Clone(challenge), bytes.Clone(retirement)
		}
		r := readWUA(t, f.wuaStore)
		if len(r.Attempts) != 0 || r.Reusable.RetiredFloor != n || r.Sequence != n || len(r.Reusable.Recent) != min(int(n), wua.MaxRecentJobs) || r.LatestReadiness != nil || r.ReadinessSequence != n {
			t.Fatal("unbounded or ambiguous retirement", n, r.Reusable)
		}
		consent, _ := json.Marshal(r.Consent)
		if !bytes.Equal(consent, originalConsent) {
			t.Fatal("retirement extended grant")
		}
		if f.fenceStatus(t).Retained != 0 {
			t.Fatal("shared WUA history not compacted")
		}
		restartReusableWUA(t, f)
		status, e := f.executor.Status(ctx)
		if e != nil || status.Readiness != nil || len(status.Attempts) != 0 || len(status.Retirements) != 1 || status.InstallCapacityRemaining != 1 {
			t.Fatal("retired result advertised or new job starved", e, status)
		}
		before := f.wuaNative.prepares.Load()
		if _, e = f.executor.Accept(ctx, firstPermit); e == nil {
			t.Fatal("old permit revived")
		}
		if _, e = f.executor.Readiness(ctx, firstChallenge); e == nil {
			t.Fatal("old challenge revived")
		}
		if n > 1 {
			if _, e = f.executor.Retire(ctx, firstRetirement); e == nil && n > wua.MaxRecentJobs {
				t.Fatal("pruned retirement revived")
			}
		}
		if f.wuaNative.prepares.Load() != before || f.wuaNative.calls.Load() != int64(n) {
			t.Fatal("replay accessed native adapter")
		}
		f.at.Add(1)
	}
}
func TestReusableWUARetirementCrashAfterFenceCompactionReconcilesExactIntent(t *testing.T) {
	f := newPair(t, true, true, false, false, true)
	ctx := context.Background()
	raw := reusableWUAPermit(t, f, 1)
	if _, e := f.executor.Execute(ctx, raw); e != nil {
		t.Fatal(e)
	}
	retirement := reusableWUARetirement(t, f)
	failed := false
	f.wuaStore.before = func(name string, b []byte) error {
		var r wua.ExecutorRecord
		if name == "executor.json" && json.Unmarshal(b, &r) == nil && r.Reusable != nil && r.Reusable.RetiredFloor == 1 && !failed {
			failed = true
			return errors.New("inert atomic write interruption")
		}
		return nil
	}
	if _, e := f.executor.Retire(ctx, retirement); e == nil || !failed {
		t.Fatal("retirement interruption missing", e)
	}
	r := readWUA(t, f.wuaStore)
	if !bytes.Equal(r.Reusable.Pending, retirement) || len(r.Attempts) != 1 || f.fenceStatus(t).Retained != 0 {
		t.Fatal("exact pending intent/compacted owner missing")
	}
	f.wuaStore.before = nil
	restartReusableWUA(t, f)
	r = readWUA(t, f.wuaStore)
	if r.Reusable.RetiredFloor != 1 || len(r.Reusable.Pending) != 0 || f.wuaNative.calls.Load() != 1 {
		t.Fatal("reopen reran install or failed retirement")
	}
	ack, e := f.executor.Retire(ctx, retirement)
	if e != nil {
		t.Fatal(e)
	}
	restartReusableWUA(t, f)
	again, e := f.executor.Retire(ctx, retirement)
	if e != nil || !bytes.Equal(ack, again) {
		t.Fatal("reopen resigned persisted acknowledgment", e)
	}
}
func TestReusableWUARetirementMissingCompletionAndExpiredIntentFailClosed(t *testing.T) {
	for _, mode := range []string{"cleanup_uncertain", "expiry_after_intent", "authority_after_intent", "wrong_result", "wrong_occurrence"} {
		t.Run(mode, func(t *testing.T) {
			f := newPair(t, true, true, false, false, true)
			ctx := context.Background()
			if mode == "cleanup_uncertain" {
				f.wuaNative.closeError = errors.New("inert cleanup uncertainty")
			}
			if _, e := f.executor.Execute(ctx, reusableWUAPermit(t, f, 1)); e != nil {
				t.Fatal(e)
			}
			retirement := reusableWUARetirement(t, f)
			if mode == "wrong_result" || mode == "wrong_occurrence" {
				p, _ := wua.VerifyRetirement(retirement, public(f.wuaKey))
				if mode == "wrong_result" {
					p.ResultDigest = digest("changed result")
				} else {
					p.Occurrence++
				}
				retirement, _ = wua.SignRetirement(p, f.wuaKey)
			}
			if mode == "expiry_after_intent" || mode == "authority_after_intent" {
				f.wuaStore.before = func(name string, b []byte) error {
					var r wua.ExecutorRecord
					if json.Unmarshal(b, &r) == nil && r.Reusable != nil && len(r.Reusable.Pending) > 0 {
						if mode == "expiry_after_intent" {
							f.at.Add(121)
						} else {
							f.wuaAuthority.value.Enabled = false
						}
						f.wuaStore.before = nil
					}
					return nil
				}
			}
			if _, e := f.executor.Retire(ctx, retirement); e == nil {
				t.Fatal("invalid retirement admitted")
			}
			r := readWUA(t, f.wuaStore)
			if r.Reusable.RetiredFloor != 0 || len(r.Attempts) != 1 || f.wuaNative.calls.Load() != 1 {
				t.Fatal("invalid retirement removed current job")
			}
			if mode == "expiry_after_intent" {
				restartReusableWUA(t, f)
				r = readWUA(t, f.wuaStore)
				if len(r.Reusable.Pending) == 0 || r.Reusable.RetiredFloor != 0 {
					t.Fatal("expired pending intent revived")
				}
			}
		})
	}
}
func TestReusableWUARetiredOutboxNeverRenewsExpiredEvidence(t *testing.T) {
	f := newPair(t, true, true, false, false, true)
	ctx := context.Background()
	if _, e := f.executor.Execute(ctx, reusableWUAPermit(t, f, 1)); e != nil {
		t.Fatal(e)
	}
	retirement := reusableWUARetirement(t, f)
	ack, e := f.executor.Retire(ctx, retirement)
	if e != nil {
		t.Fatal(e)
	}
	report, _ := wua.VerifyRetirementReport(ack, public(f.wuaExecutorKey))
	f.at.Store(report.ExpiresAt)
	if _, e = f.executor.Outbox(ctx, "retired", report.JobID, report.ReferenceDigest); !errors.Is(e, wua.ErrExpired) {
		t.Fatal(e)
	}
	restartReusableWUA(t, f)
	r := readWUA(t, f.wuaStore)
	if !bytes.Equal(r.Reusable.Recent[0].Report, ack) || f.wuaNative.calls.Load() != 1 {
		t.Fatal("expired acknowledgment changed")
	}
}

// The handshake store is inert serialized state with the public transaction
// contract and final-check boundary; it does not claim native SQLite acceptance.
type reusableWUAHandshakeStore struct {
	raw []byte
	f   *pairedDomains
}

func (s *reusableWUAHandshakeStore) WindowsUpdateEnrollmentBinding() enrollmentstate.Binding {
	return enrollmentstate.Binding{InstanceID: s.f.consent.Binding.ManagerID, Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory}
}
func (s *reusableWUAHandshakeStore) WindowsUpdateJobTransaction(ctx context.Context, b wua.Binding, k ed25519.PublicKey, at time.Time, fn func(*wua.Record, wua.Current, time.Time) error) (wua.Record, time.Time, error) {
	before, e := wua.DecodeRecord(s.raw)
	if e != nil {
		return wua.Record{}, at, e
	}
	r, e := wua.DecodeRecord(s.raw)
	if e != nil {
		return wua.Record{}, at, e
	}
	if b != r.Consent.Binding || !bytes.Equal(k, r.PublicKey) {
		return wua.Record{}, at, wua.ErrAuthority
	}
	if e = fn(&r, s.f.wuaAuthority.value, at); e != nil {
		return before, at, e
	}
	if e = wua.CheckFinal(ctx); e != nil {
		return before, at, e
	}
	if e = wua.CheckReusableTransition(before, r); e != nil {
		return before, at, e
	}
	raw, e := wua.EncodeRecord(r)
	if e != nil {
		return before, at, e
	}
	s.raw = raw
	return r, at, nil
}
func TestReusableWUAFortyManagerEndpointSignedHandshakesAcrossReopen(t *testing.T) {
	f := newPair(t, true, true, false, false, true)
	ctx := context.Background()
	r, e := wua.NewRecordWithExecutor(f.consent, public(f.wuaKey), public(f.wuaExecutorKey), f.now().Unix())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := wua.EncodeRecord(r)
	if e != nil {
		t.Fatal(e)
	}
	store := &reusableWUAHandshakeStore{raw: raw, f: f}
	actor, device := id("operator_", 10), f.consent.Binding.DeviceID
	openManager := func() *wua.Manager {
		m, err := wua.OpenTransactional(ctx, store, f.consent.Binding, f.wuaKey, f.now)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.ConfigureOperatorPolicy(func(a string) bool { return a == actor }); err != nil {
			t.Fatal(err)
		}
		return m
	}
	manager := openManager()
	var lastAck []byte
	for n := uint64(1); n <= 40; n++ {
		job := id("update_", int(n)+2000)
		f.wuaNative.readiness.Selection.Revision = uint32(n)
		if e = manager.Request(ctx, device, actor, job, f.wuaNative.readiness.Selection); e != nil {
			t.Fatal("request", n, e)
		}
		if len(lastAck) > 0 {
			if e = manager.Report(ctx, lastAck); e != nil {
				t.Fatal("prior acknowledgment starved new job", n, e)
			}
		}
		challenge, err := manager.ClaimReadiness(ctx, job)
		if err != nil {
			t.Fatal("claim readiness", n, err)
		}
		readiness, err := f.executor.Readiness(ctx, challenge)
		if err != nil {
			t.Fatal("endpoint readiness", n, err)
		}
		status, err := f.executor.Status(ctx)
		if err != nil || len(status.MutationReport) == 0 {
			t.Fatal("fresh shared status", n, err)
		}
		if e = manager.Report(ctx, status.MutationReport); e != nil {
			t.Fatal("shared report", n, e)
		}
		if e = manager.Report(ctx, readiness); e != nil {
			t.Fatal("readiness report", n, e)
		}
		view, err := manager.View(ctx, device, actor)
		if err != nil || view.Job == nil || view.Job.Preview == nil {
			t.Fatal("view", n, err)
		}
		if e = manager.Approve(ctx, device, actor, job, view.Job.Preview.Digest, true); e != nil {
			t.Fatal("approve", n, e)
		}
		permit, err := manager.Claim(ctx, job)
		if err != nil {
			t.Fatal("claim", n, err)
		}
		parsed, err := wua.Verify(permit, public(f.wuaKey))
		if err != nil || parsed.Sequence != n || parsed.Version != wua.ReusablePermitVersion {
			t.Fatal("occurrence", n, err)
		}
		result, err := f.executor.Execute(ctx, permit)
		if err != nil || result.Outcome != "succeeded" {
			t.Fatal("execute", n, err)
		}
		proof, err := f.executor.Outbox(ctx, "result", job, actionpermit.Digest(permit))
		if err != nil {
			t.Fatal(err)
		}
		if e = manager.Report(ctx, proof); e != nil {
			t.Fatal("result report", n, e)
		}
		if e = manager.Retire(ctx, device, actor, job, n, actionpermit.Digest(permit), actionpermit.Digest(proof), true); e != nil {
			t.Fatal("manager retirement", n, e)
		}
		pending, err := manager.Pending(ctx)
		if err != nil || pending == nil || pending.Kind != "retire" {
			t.Fatal("pending retirement", n, err)
		}
		retire, err := manager.ClaimRetirement(ctx, job)
		if err != nil {
			t.Fatal("retirement claim", n, err)
		}
		repeated, err := manager.ClaimRetirement(ctx, job)
		if err != nil || !bytes.Equal(retire, repeated) {
			t.Fatal("lost metadata claim cannot reconcile", n, err)
		}
		ack, err := f.executor.Retire(ctx, retire)
		if err != nil {
			t.Fatal("endpoint retirement", n, err)
		}
		if e = manager.Report(ctx, ack); e != nil {
			t.Fatal("retirement report", n, e)
		}
		if e = manager.Report(ctx, ack); e != nil {
			t.Fatal("retirement report replay", n, e)
		}
		saved, err := wua.DecodeRecord(store.raw)
		if err != nil || saved.RetiredFloor != n || len(saved.Recent) != min(int(n), wua.MaxRecentJobs) || len(saved.Jobs) != 1 {
			t.Fatal("manager bounded history", n, err)
		}
		endpoint := readWUA(t, f.wuaStore)
		if endpoint.Reusable.RetiredFloor != n || endpoint.Sequence != saved.Sequence || f.wuaNative.calls.Load() != int64(n) {
			t.Fatal("endpoint/manager floor mismatch", n)
		}
		lastAck = bytes.Clone(ack)
		manager.Close()
		restartReusableWUA(t, f)
		manager = openManager()
		f.at.Add(1)
	}
	manager.Close()
}

func TestReusableWUARetirementExpiresDuringAcknowledgmentSaveWithoutResigning(t *testing.T) {
	f := newPair(t, true, true, false, false, true)
	ctx := context.Background()
	if _, e := f.executor.Execute(ctx, reusableWUAPermit(t, f, 1)); e != nil {
		t.Fatal(e)
	}
	retirement := reusableWUARetirement(t, f)
	f.wuaStore.before = func(_ string, b []byte) error {
		var r wua.ExecutorRecord
		if json.Unmarshal(b, &r) == nil && r.Reusable != nil && len(r.Reusable.Recent) == 1 {
			ack, _ := wua.VerifyRetirementReport(r.Reusable.Recent[0].Report, public(f.wuaExecutorKey))
			f.at.Store(ack.ExpiresAt)
			f.wuaStore.before = nil
		}
		return nil
	}
	if out, e := f.executor.Retire(ctx, retirement); !errors.Is(e, wua.ErrExpired) || len(out) != 0 {
		t.Fatal("expired acknowledgment escaped", e)
	}
	saved := readWUA(t, f.wuaStore)
	original := bytes.Clone(saved.Reusable.Recent[0].Report)
	restartReusableWUA(t, f)
	if out, e := f.executor.Retire(ctx, retirement); !errors.Is(e, wua.ErrExpired) || len(out) != 0 {
		t.Fatal("expired retirement replay escaped", e)
	}
	saved = readWUA(t, f.wuaStore)
	if !bytes.Equal(original, saved.Reusable.Recent[0].Report) || f.wuaNative.calls.Load() != 1 {
		t.Fatal("expiry re-signed or reran")
	}
	f.at.Add(-120)
	if _, e := f.executor.Retire(ctx, retirement); !errors.Is(e, wua.ErrExpired) {
		t.Fatal("rollback revived retirement", e)
	}
}

func TestReusableWUARetirementRecoversOnlyExactSavedLostRelease(t *testing.T) {
	f := newPair(t, true, true, false, false, true)
	ctx := context.Background()
	f.shared.FailNextRelease()
	if result, e := f.executor.Execute(ctx, reusableWUAPermit(t, f, 1)); e != nil || result.Outcome != "succeeded" {
		t.Fatal(e)
	}
	if st := f.fenceStatus(t); !st.Blocked || st.Phase != "completion_recorded" {
		t.Fatal("lost release fixture did not retain owner", st)
	}
	retirement := reusableWUARetirement(t, f)
	if _, e := f.executor.Retire(ctx, retirement); e != nil {
		t.Fatal("exact release evidence did not recover", e)
	}
	if st := f.fenceStatus(t); st.Blocked || st.Retained != 0 || f.wuaNative.calls.Load() != 1 {
		t.Fatal("retirement did not safely compact exact release", st)
	}
}
