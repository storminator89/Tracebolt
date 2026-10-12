package windowsmutationfence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/windowsstate"
)

// These fixtures model short exclusive transactions and durable bytes only.
// They never create native files, ACLs, processes, services, or host grants.
type memoryFence struct {
	mu                sync.Mutex
	exists            bool
	broken            bool
	raw               []byte
	opens             int
	writes            int
	closes            int
	failOpen          int
	failWrite         int
	commitFailedWrite bool
	pending           bool
	failClose         int
	afterOpen         func()
}
type memoryStore struct {
	f      *memoryFence
	closed bool
}

func (f *memoryFence) open(create bool) (storage, error) {
	if !f.mu.TryLock() {
		return nil, ErrUnavailable
	}
	f.opens++
	if f.opens == f.failOpen || f.broken || f.pending {
		f.mu.Unlock()
		return nil, ErrIntegrity
	}
	if create {
		if f.exists {
			f.mu.Unlock()
			return nil, fs.ErrExist
		}
		f.exists = true
	} else if !f.exists {
		f.mu.Unlock()
		return nil, fs.ErrNotExist
	}
	if f.afterOpen != nil {
		f.afterOpen()
	}
	return &memoryStore{f: f}, nil
}
func (s *memoryStore) Read(name string) ([]byte, error) {
	if s.closed || name != stateFile || s.f.raw == nil {
		return nil, fs.ErrNotExist
	}
	return bytes.Clone(s.f.raw), nil
}
func (s *memoryStore) Write(name string, raw []byte) error {
	if s.closed || name != stateFile {
		return ErrIntegrity
	}
	f := s.f
	f.writes++
	if f.writes == f.failWrite {
		if f.commitFailedWrite {
			f.raw = bytes.Clone(raw)
		} else {
			f.pending = true
		}
		return ErrUncertain
	}
	f.raw = bytes.Clone(raw)
	return nil
}
func (s *memoryStore) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.f.closes++
	fail := s.f.closes == s.f.failClose
	s.f.mu.Unlock()
	if fail {
		return ErrUncertain
	}
	return nil
}
func testDigest(s string) string { return actionpermit.Digest([]byte(s)) }
func testPlan() Plan {
	return Plan{Identity: Identity{"manager_" + strings.Repeat("1", 32), "agent_" + strings.Repeat("2", 32), testDigest("incarnation")}, PlanDigest: testDigest("plan"), MSIOfferDigest: testDigest("msi-offer"), WUAOfferDigest: testDigest("wua-offer"), MSIArtifactDigest: testDigest("msi-artifact"), WUAArtifactDigest: testDigest("wua-artifact")}
}
func testRoster(p Plan, id string) Roster {
	return Roster{Plan: p, FenceID: id, MSI: Participant{ManagedMSI, testDigest("msi-binding"), testDigest("msi-grant"), testDigest("msi-manager"), testDigest("msi-executor")}, WUA: Participant{CachedWUA, testDigest("wua-binding"), testDigest("wua-grant"), testDigest("wua-manager"), testDigest("wua-executor")}}
}
func testActivation() Activation {
	return Activation{testDigest("msi-receipt"), testDigest("msi-config"), testDigest("wua-receipt"), testDigest("wua-config")}
}
func testOwner(domain string, seq uint64) Owner {
	prefix := "update_"
	if domain == ManagedMSI {
		prefix = "transfer_"
	}
	id := fmt.Sprintf("%s%032x", prefix, seq)
	o := Owner{Domain: domain, JobID: id, Sequence: seq, PermitDigest: testDigest(domain + id)}
	if domain == ManagedMSI {
		o.TransferID = id
	}
	return o
}
func testSetup(t *testing.T) (*memoryFence, Roster, *atomic.Int64) {
	t.Helper()
	f := &memoryFence{}
	now := &atomic.Int64{}
	now.Store(1800000000)
	p := testPlan()
	id, e := beginSetup(context.Background(), p, now.Load(), f.open)
	if e != nil {
		t.Fatal(e)
	}
	r := testRoster(p, id)
	if e = setupChange(context.Background(), r, nil, now.Load(), f.open); e != nil {
		t.Fatal(e)
	}
	a := testActivation()
	if e = setupChange(context.Background(), r, &a, now.Load(), f.open); e != nil {
		t.Fatal(e)
	}
	return f, r, now
}
func testSession(t *testing.T, f *memoryFence, r Roster, d string, now *atomic.Int64) *Session {
	t.Helper()
	s, e := openSession(context.Background(), r, d, func() time.Time { return time.Unix(now.Load(), 0) }, f.open)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func mustReserve(t *testing.T, s *Session, o Owner) *Capability {
	t.Helper()
	c, e := s.Reserve(context.Background(), o)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func start(t *testing.T, s *Session, c *Capability) {
	t.Helper()
	if e := s.Dispatch(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	if e := s.CheckStart(context.Background(), c, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
}
func terminal(t *testing.T, c *Capability, now int64) Receipt {
	t.Helper()
	r, e := c.Completion(testDigest(c.owner.JobID+"-result"), "completed", now)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func exact(saved Receipt) VerifyReceipt {
	return func(r Receipt) error {
		if r != saved {
			return ErrIntegrity
		}
		return nil
	}
}

func TestFreshSetupStagesAndImmutableRoster(t *testing.T) {
	ctx := context.Background()
	p := testPlan()
	f := &memoryFence{}
	now := int64(1800000000)
	id, e := beginSetup(ctx, p, now, f.open)
	if e != nil {
		t.Fatal(e)
	}
	r := testRoster(p, id)
	clock := func() time.Time { return time.Unix(now, 0) }
	if _, e = openSession(ctx, r, ManagedMSI, clock, f.open); e == nil {
		t.Fatal("intent alone activated")
	}
	a := testActivation()
	if e = setupChange(ctx, r, &a, now, f.open); e == nil {
		t.Fatal("activation without roster")
	}
	if e = setupChange(ctx, r, nil, now, f.open); e != nil {
		t.Fatal(e)
	}
	if _, e = openSession(ctx, r, ManagedMSI, clock, f.open); !errors.Is(e, ErrInactive) {
		t.Fatal("staged roster runnable", e)
	}
	if e = setupChange(ctx, r, nil, now, f.open); e == nil {
		t.Fatal("rebound roster")
	}
	partial := a
	partial.WUAReceiptDigest = ""
	if e = setupChange(ctx, r, &partial, now, f.open); e == nil {
		t.Fatal("partial activation")
	}
	if e = setupChange(ctx, r, &a, now, f.open); e != nil {
		t.Fatal(e)
	}
	if e = setupChange(ctx, r, &a, now, f.open); e == nil {
		t.Fatal("activation repeated")
	}
	if _, e = beginSetup(ctx, p, now, f.open); e == nil {
		t.Fatal("existing root adopted")
	}
	if _, e = openSession(ctx, r, CachedWUA, clock, f.open); e != nil {
		t.Fatal(e)
	}
	changed := r
	changed.WUA.GrantDigest = testDigest("another-grant")
	if _, e = openSession(ctx, changed, ManagedMSI, clock, f.open); e == nil {
		t.Fatal("changed participant accepted")
	}
	changed = r
	changed.Plan.Identity.IncarnationDigest = testDigest("new-incarnation")
	if _, e = openSession(ctx, changed, ManagedMSI, clock, f.open); e == nil {
		t.Fatal("new identity adopted")
	}
}
func TestTwoDomainsHaveOneOwner(t *testing.T) {
	f, r, now := testSetup(t)
	msi := testSession(t, f, r, ManagedMSI, now)
	wua := testSession(t, f, r, CachedWUA, now)
	ready := make(chan struct{})
	type result struct {
		domain string
		c      *Capability
		e      error
	}
	out := make(chan result, 2)
	for _, s := range []*Session{msi, wua} {
		go func(s *Session) {
			<-ready
			c, e := s.Reserve(context.Background(), testOwner(s.domain, 1))
			out <- result{s.domain, c, e}
		}(s)
	}
	close(ready)
	a, b := <-out, <-out
	if (a.e == nil) == (b.e == nil) {
		t.Fatalf("expected one reservation: %v %v", a.e, b.e)
	}
	winner, loser := a, b
	if a.e != nil {
		winner, loser = b, a
	}
	if loser.c != nil {
		t.Fatal("loser got capability")
	}
	if loser.e != ErrBusy && loser.e != ErrUnavailable {
		t.Fatal(loser.e)
	}
	st, e := msi.Status(context.Background())
	if e != nil || !st.Blocked || st.Domain != winner.domain || st.Phase != "reserved" || st.Validate() != nil {
		t.Fatalf("status %+v %v", st, e)
	}
	// Native installation owns durable state, not a held file/process lock.
	if !f.mu.TryLock() {
		t.Fatal("installation-long lock held")
	}
	f.mu.Unlock()
	if _, e = wua.Reserve(context.Background(), testOwner(CachedWUA, 2)); e != ErrBusy {
		t.Fatal("new contender admitted", e)
	}
}
func TestRestartAndCopiedCapabilityCannotDispatch(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, ManagedMSI, now)
	c := mustReserve(t, s, testOwner(ManagedMSI, 1))
	copied := *c
	if e := s.Dispatch(context.Background(), &copied); e != ErrConsumed {
		t.Fatal("copied capability dispatched", e)
	}
	if e := s.Dispatch(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	next := testSession(t, f, r, ManagedMSI, now)
	if e := next.CheckStart(context.Background(), c, func() error { return nil }); e != ErrConsumed {
		t.Fatal("restart recreated permission", e)
	}
	if _, e := next.Reserve(context.Background(), testOwner(ManagedMSI, 1)); e != ErrBusy {
		t.Fatal(e)
	}
	if _, e := c.Completion(testDigest("result"), "completed", now.Load()); e == nil {
		t.Fatal("receipt before start")
	}
	if e := s.CheckStart(context.Background(), c, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := s.CheckStart(context.Background(), c, func() error { t.Fatal("callback twice"); return nil }); e != ErrConsumed {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	now.Add(365 * 24 * 3600)
	st, e := next.Status(context.Background())
	if e != nil || !st.Blocked || st.Phase != "dispatch_intent" {
		t.Fatal("time/close released owner", st, e)
	}
}
func TestFinalAuthorityAfterOpenWaitAndOutsideTransaction(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, CachedWUA, now)
	c := mustReserve(t, s, testOwner(CachedWUA, 1))
	if e := s.Dispatch(context.Background(), c); e != nil {
		t.Fatal(e)
	}
	deadline := now.Load() + 1
	f.afterOpen = func() { now.Add(2); f.afterOpen = nil }
	expired := errors.New("original start deadline expired")
	called := false
	e := s.CheckStart(context.Background(), c, func() error {
		called = true
		if e := s.Verify(context.Background()); e != nil {
			t.Fatal("callback nested protected transaction", e)
		}
		if now.Load() >= deadline {
			return expired
		}
		return nil
	})
	if !called || e != expired {
		t.Fatal("authority not checked after wait", e)
	}
	if e = s.CheckStart(context.Background(), c, func() error { return nil }); e != ErrConsumed {
		t.Fatal("failed start retried", e)
	}
	st, e := s.Status(context.Background())
	if e != nil || !st.Blocked {
		t.Fatal("failed start auto-released", e)
	}
}
func TestDomainDurabilityRequiredBeforeRelease(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, CachedWUA, now)
	c := mustReserve(t, s, testOwner(CachedWUA, 1))
	start(t, s, c)
	receipt := terminal(t, c, now.Load())
	notSaved := errors.New("domain completion not durable")
	if e := s.Complete(context.Background(), c, receipt, func(Receipt) error { return notSaved }); e != notSaved {
		t.Fatal(e)
	}
	if e := s.Complete(context.Background(), c, receipt, nil); e == nil {
		t.Fatal("no durability verifier")
	}
	st, _ := s.Status(context.Background())
	if !st.Blocked || st.Phase != "dispatch_intent" {
		t.Fatal(st)
	}
	verify := func(got Receipt) error {
		if !f.mu.TryLock() {
			t.Fatal("domain verifier ran under fence transaction")
		}
		f.mu.Unlock()
		return exact(receipt)(got)
	}
	if e := s.Complete(context.Background(), c, receipt, verify); e != nil {
		t.Fatal(e)
	}
	st, e := s.Status(context.Background())
	if e != nil || st.Blocked || st.Retained != 1 || st.Validate() != nil {
		t.Fatal(st, e)
	}
	if _, e = s.Reserve(context.Background(), testOwner(CachedWUA, 1)); e != ErrConsumed {
		t.Fatal("consumed owner replayed", e)
	}
	if _, e = s.Reserve(context.Background(), testOwner(CachedWUA, 2)); e != nil {
		t.Fatal(e)
	}
}
func TestExactSavedReceiptFinishesLostRelease(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, ManagedMSI, now)
	c := mustReserve(t, s, testOwner(ManagedMSI, 1))
	start(t, s, c)
	saved := terminal(t, c, now.Load())
	raw, e := json.Marshal(saved)
	if e != nil {
		t.Fatal(e)
	}
	var restored Receipt
	if e = json.Unmarshal(raw, &restored); e != nil || restored != saved {
		t.Fatal(e)
	}
	f.failOpen = f.opens + 2 // Commit completion evidence; fail before release transaction.
	if e = s.Complete(context.Background(), c, saved, exact(saved)); e == nil {
		t.Fatal("injected release failure ignored")
	}
	st, e := s.Status(context.Background())
	if e != nil || st.Phase != "completion_recorded" || st.Recovery != "exact_terminal_receipt" || !st.Blocked {
		t.Fatal(st, e)
	}
	_ = s.Close()
	restarted := testSession(t, f, r, ManagedMSI, now)
	altered := restored
	altered.ResultDigest = testDigest("forged result")
	if e = restarted.Recover(context.Background(), altered, func(Receipt) error { return nil }); e == nil {
		t.Fatal("changed saved receipt released owner")
	}
	if e = restarted.Recover(context.Background(), restored, exact(saved)); e != nil {
		t.Fatal(e)
	}
	if e = restarted.Recover(context.Background(), restored, exact(saved)); e != nil {
		t.Fatal("exact lost acknowledgement not idempotent", e)
	}
	st, e = restarted.Status(context.Background())
	if e != nil || st.Blocked {
		t.Fatal(st, e)
	}
	if _, e = restarted.Reserve(context.Background(), testOwner(ManagedMSI, 2)); e != ErrCapacity {
		t.Fatal("MSI lifetime capacity reset", e)
	}
	wua := testSession(t, f, r, CachedWUA, now)
	if _, e = wua.Reserve(context.Background(), testOwner(CachedWUA, 1)); e != nil {
		t.Fatal(e)
	}
}
func TestSavedDomainReceiptAfterCrashBeforeFenceCompletion(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, CachedWUA, now)
	c := mustReserve(t, s, testOwner(CachedWUA, 1))
	start(t, s, c)
	saved := terminal(t, c, now.Load())
	_ = s.Close()
	restarted := testSession(t, f, r, CachedWUA, now)
	bad := saved
	bad.CompletedAt++
	if e := restarted.Recover(context.Background(), bad, exact(saved)); e == nil {
		t.Fatal("nonexact domain proof")
	}
	if e := restarted.Recover(context.Background(), saved, exact(saved)); e != nil {
		t.Fatal(e)
	}
	if e := restarted.Dispatch(context.Background(), c); e != ErrConsumed {
		t.Fatal("recovery minted dispatch", e)
	}
}
func TestMissingReplacedPendingAndRollbackRemainBlocked(t *testing.T) {
	for _, fault := range []string{"missing-root", "missing-file", "replacement", "pending", "clock-rollback"} {
		t.Run(fault, func(t *testing.T) {
			f, r, now := testSetup(t)
			s := testSession(t, f, r, ManagedMSI, now)
			c := mustReserve(t, s, testOwner(ManagedMSI, 1))
			if e := s.Dispatch(context.Background(), c); e != nil {
				t.Fatal(e)
			}
			switch fault {
			case "missing-root":
				f.exists = false
			case "missing-file":
				f.raw = nil
			case "replacement":
				v, e := decode(f.raw)
				if e != nil {
					t.Fatal(e)
				}
				v.FenceID = testDigest("new-root")
				v.Roster.FenceID = v.FenceID
				f.raw, _ = json.Marshal(v)
			case "pending":
				f.pending = true
			case "clock-rollback":
				now.Add(-1)
			}
			called := false
			if e := s.CheckStart(context.Background(), c, func() error { called = true; return nil }); e == nil || called {
				t.Fatal("uncertain state dispatched", e)
			}
			st, e := s.Status(context.Background())
			if e == nil || !st.Blocked || st.Active || st.Validate() != nil {
				t.Fatal(st, e)
			}
		})
	}
}
func TestUncertainReserveAndDispatchNeverYieldRunnableCapability(t *testing.T) {
	for _, at := range []string{"reserve-write", "reserve-close", "dispatch-write", "dispatch-close"} {
		t.Run(at, func(t *testing.T) {
			f, r, now := testSetup(t)
			s := testSession(t, f, r, ManagedMSI, now)
			if at == "reserve-write" {
				f.failWrite = f.writes + 1
				f.commitFailedWrite = true
			}
			if at == "reserve-close" {
				f.failClose = f.closes + 1
			}
			c, e := s.Reserve(context.Background(), testOwner(ManagedMSI, 1))
			if strings.HasPrefix(at, "reserve-") {
				if e == nil || c != nil {
					t.Fatal("uncertain reserve returned capability", e)
				}
				st, _ := s.Status(context.Background())
				if !st.Blocked {
					t.Fatal(st)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if at == "dispatch-write" {
				f.failWrite = f.writes + 1
				f.commitFailedWrite = true
			} else {
				f.failClose = f.closes + 1
			}
			if e = s.Dispatch(context.Background(), c); e == nil {
				t.Fatal("failure not surfaced")
			}
			called := false
			if e = s.CheckStart(context.Background(), c, func() error { called = true; return nil }); e == nil || called {
				t.Fatal("uncertain dispatch granted start", e)
			}
		})
	}
}
func TestBoundedRetainedOwnersAndNoCrossDomainReceipt(t *testing.T) {
	f, r, now := testSetup(t)
	wua := testSession(t, f, r, CachedWUA, now)
	msi := testSession(t, f, r, ManagedMSI, now)
	for i := uint64(1); i <= 32; i++ {
		c := mustReserve(t, wua, testOwner(CachedWUA, i))
		start(t, wua, c)
		saved := terminal(t, c, now.Load())
		if i == 1 {
			if e := msi.Recover(context.Background(), saved, exact(saved)); e == nil {
				t.Fatal("MSI accepted WUA receipt")
			}
		}
		if e := wua.Complete(context.Background(), c, saved, exact(saved)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := wua.Reserve(context.Background(), testOwner(CachedWUA, 33)); e != ErrCapacity {
		t.Fatal(e)
	}
	c := mustReserve(t, msi, testOwner(ManagedMSI, 1))
	start(t, msi, c)
	saved := terminal(t, c, now.Load())
	if e := msi.Complete(context.Background(), c, saved, exact(saved)); e != nil {
		t.Fatal(e)
	}
	st, e := msi.Status(context.Background())
	if e != nil || st.Retained != MaxOwners || st.Blocked || st.Validate() != nil {
		t.Fatal(st, e)
	}
}
func TestProductionSchemaAndPublicRedaction(t *testing.T) {
	o := StoreOptions()
	if !o.InstallerOnly || o.RuntimeSID != "" || o.Create || len(o.Directories) != 0 || len(o.Names) != 1 || o.Names[0] != stateFile || o.MaxBytes != MaxBytes {
		t.Fatal("unsafe production options", o)
	}
	if o.LockName == o.TempName || o.LockName == stateFile || o.TempName == stateFile {
		t.Fatal(o)
	}
	f, r, now := testSetup(t)
	s := testSession(t, f, r, ManagedMSI, now)
	c := mustReserve(t, s, testOwner(ManagedMSI, 1))
	start(t, s, c)
	saved := terminal(t, c, now.Load())
	if strings.Contains(fmt.Sprintf("%+v %#v", c, saved), saved.proof) {
		t.Fatal("private proof logged")
	}
	if _, e := json.Marshal(c); e == nil {
		t.Fatal("capability serialized")
	}
	st, e := s.Status(context.Background())
	raw, _ := json.Marshal(st)
	if e != nil || bytes.Contains(raw, []byte(saved.proof)) || bytes.Contains(raw, []byte(c.owner.PermitDigest)) || st.Validate() != nil {
		t.Fatal("unsafe status", e)
	}
	if (Status{}).Validate() == nil {
		t.Fatal("zero snapshot implies idle")
	}
	invalid := st
	invalid.Blocked = false
	if invalid.Validate() == nil {
		t.Fatal("owner snapshot marked idle")
	}
	malformed, _ := json.Marshal(saved)
	malformed = append([]byte(`{"unknown":true,`), malformed[1:]...)
	var q Receipt
	if json.Unmarshal(malformed, &q) == nil {
		t.Fatal("noncanonical receipt accepted")
	}
	if s.Matches(r, CachedWUA) || !s.Matches(r, ManagedMSI) {
		t.Fatal("session domain mismatch")
	}
	changed := r
	changed.WUA.ExecutorKeyDigest = testDigest("another-key")
	if s.Matches(changed, ManagedMSI) {
		t.Fatal("session roster mismatch")
	}
}
func TestInstallerOnlySchemaCannotNameObserver(t *testing.T) {
	// ACL rejection itself belongs to windowsstate's descriptor/policy fixtures.
	// This boundary never exposes Options to production callers for overriding.
	o := StoreOptions()
	o.RuntimeSID = "S-1-5-80-1-2-3-4-5"
	if _, e := windowsstate.Open(`C:\ProgramData\Tracebolt\windows-mutation-fence`, o); e != windowsstate.ErrPolicy {
		t.Fatal("observer joined installer-only schema", e)
	}
}

func TestParticipantActivationPinsAndStagedGuard(t *testing.T) {
	ctx := context.Background()
	p := testPlan()
	f := &memoryFence{}
	at := int64(1800000000)
	id, e := beginSetup(ctx, p, at, f.open)
	if e != nil {
		t.Fatal(e)
	}
	r := testRoster(p, id)
	if e = verifyStaged(ctx, r, f.open); e == nil {
		t.Fatal("unbound roster staged")
	}
	if e = setupChange(ctx, r, nil, at, f.open); e != nil {
		t.Fatal(e)
	}
	if e = verifyStaged(ctx, r, f.open); e != nil {
		t.Fatal(e)
	}
	wrong := r
	wrong.MSI.GrantDigest = testDigest("wrong grant")
	if e = verifyStaged(ctx, wrong, f.open); e == nil {
		t.Fatal("different staged roster")
	}
	a := testActivation()
	if e = setupChange(ctx, r, &a, at, f.open); e != nil {
		t.Fatal(e)
	}
	if e = verifyStaged(ctx, r, f.open); e == nil {
		t.Fatal("active state reused as staging")
	}
	now := &atomic.Int64{}
	now.Store(at)
	for _, d := range []string{ManagedMSI, CachedWUA} {
		s := testSession(t, f, r, d, now)
		config, receipt := a.MSIConfigDigest, a.MSIReceiptDigest
		if d == CachedWUA {
			config, receipt = a.WUAConfigDigest, a.WUAReceiptDigest
		}
		if e = s.VerifyParticipant(ctx, config, receipt); e != nil {
			t.Fatal(e)
		}
		if e = s.VerifyParticipant(ctx, config, testDigest("other receipt")); e == nil {
			t.Fatal("activation receipt mismatch")
		}
		if e = s.VerifyParticipant(ctx, testDigest("other config"), receipt); e == nil {
			t.Fatal("activation config mismatch")
		}
	}
}

func TestOldReleasedReceiptCannotReleaseNewOwner(t *testing.T) {
	f, r, now := testSetup(t)
	s := testSession(t, f, r, CachedWUA, now)
	first := mustReserve(t, s, testOwner(CachedWUA, 1))
	start(t, s, first)
	saved := terminal(t, first, now.Load())
	if e := s.Complete(context.Background(), first, saved, exact(saved)); e != nil {
		t.Fatal(e)
	}
	next := mustReserve(t, s, testOwner(CachedWUA, 2))
	start(t, s, next)
	if e := s.Recover(context.Background(), saved, exact(saved)); e != nil {
		t.Fatal(e)
	}
	st, e := s.Status(context.Background())
	if e != nil || !st.Blocked || st.JobID != next.owner.JobID || st.Phase != "dispatch_intent" {
		t.Fatal("old terminal receipt released another owner", st, e)
	}
}

func TestUncertainFinalStartWriteNeverCallsNativeGuard(t *testing.T) {
	for _, closeFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(closeFailure), func(t *testing.T) {
			f, r, now := testSetup(t)
			s := testSession(t, f, r, ManagedMSI, now)
			c := mustReserve(t, s, testOwner(ManagedMSI, 1))
			if e := s.Dispatch(context.Background(), c); e != nil {
				t.Fatal(e)
			}
			if closeFailure {
				f.failClose = f.closes + 1
			} else {
				f.failWrite = f.writes + 1
				f.commitFailedWrite = true
			}
			called := false
			if e := s.CheckStart(context.Background(), c, func() error { called = true; return nil }); e == nil || called {
				t.Fatal("uncertain final guard proceeded", e)
			}
			if _, e := c.Completion(testDigest("not run"), "completed", now.Load()); e == nil {
				t.Fatal("failed start made terminal receipt")
			}
			restarted := testSession(t, f, r, ManagedMSI, now)
			st, e := restarted.Status(context.Background())
			if e != nil || !st.Blocked {
				t.Fatal(st, e)
			}
		})
	}
}
