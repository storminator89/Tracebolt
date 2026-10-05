//go:build linux

package actionstate

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
)

var testNow = time.Date(2026, 10, 5, 13, 0, 0, 0, time.UTC)

func pins() actionpermit.LocalPins {
	key := fixtureKey()
	return actionpermit.LocalPins{Enabled: true, ManagerID: "manager_" + strings.Repeat("1", 32), PublicKey: key.Public().(ed25519.PublicKey), EndpointID: "agent_" + strings.Repeat("2", 32), IncarnationDigest: actionpermit.Digest([]byte("inert incarnation")), RootPolicyDigest: actionpermit.Digest([]byte("inert local policy")), MaxLifetimeSeconds: 60, MaxFutureSkewSeconds: 0, Services: []actionpermit.ServiceRule{{Unit: "fixture.service", UnitPolicyDigest: actionpermit.Digest([]byte("inert unit policy"))}}}
}
func fixtureKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32)) }
func verifier(t testing.TB) actionpermit.Verifier {
	t.Helper()
	v, e := actionpermit.NewVerifier(pins())
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func fixture(t *testing.T) (*State, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "actions")
	s, e := Initialize(context.Background(), dir, verifier(t))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, dir
}
func permit(t testing.TB, sequence uint64) actionpermit.Permit {
	t.Helper()
	c := pins()
	plan := actionpermit.Plan{Version: actionpermit.PlanVersion, Action: actionpermit.TryRestartService, Unit: c.Services[0].Unit, UnitPolicyDigest: c.Services[0].UnitPolicyDigest}
	d, e := actionpermit.PlanDigest(plan)
	if e != nil {
		t.Fatal(e)
	}
	return actionpermit.Permit{Version: actionpermit.Version, ManagerID: c.ManagerID, KeyID: actionpermit.Digest(c.PublicKey), EndpointID: c.EndpointID, IncarnationDigest: c.IncarnationDigest, JobID: fmt.Sprintf("action_%032x", sequence), Sequence: sequence, Plan: plan, PlanDigest: d, OperatorID: "operator_" + strings.Repeat("3", 32), ApprovalDigest: actionpermit.Digest([]byte("inert approval")), RootPolicyDigest: c.RootPolicyDigest, IssuedAt: testNow.Unix(), NotBefore: testNow.Unix(), StartDeadline: testNow.Unix() + 60}
}
func signed(t testing.TB, p actionpermit.Permit) []byte {
	t.Helper()
	message, e := actionpermit.SigningMessage(p)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := actionpermit.Encode(p, ed25519.Sign(fixtureKey(), message))
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func read(t testing.TB, p string) []byte {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func requireErr(t testing.TB, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestAdmissionDuplicateAndRecovery(t *testing.T) {
	s, dir := fixture(t)
	p := permit(t, 777)
	raw := signed(t, p)
	got, e := s.Admit(context.Background(), raw, testNow)
	if e != nil || got.Phase != Admitted || got.Permit != p || !got.ConsumedAt.Equal(testNow) {
		t.Fatal(got, e)
	}
	disk := read(t, filepath.Join(dir, stateName))
	for _, now := range []time.Time{testNow, testNow.Add(time.Hour), testNow.Add(-time.Hour)} {
		duplicate, e := s.Admit(context.Background(), raw, now)
		if e != nil || duplicate != got {
			t.Fatal("duplicate changed original", duplicate, e)
		}
		if !bytes.Equal(disk, read(t, filepath.Join(dir, stateName))) {
			t.Fatal("duplicate rewrote state")
		}
	}
	if _, e = s.Admit(context.Background(), signed(t, permit(t, 778)), testNow); !errors.Is(e, ErrBusy) {
		t.Fatal(e)
	}
	p.OperatorID = "operator_" + strings.Repeat("a", 32)
	_, e = s.Admit(context.Background(), signed(t, p), testNow)
	requireErr(t, e, ErrConflict)
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(context.Background(), dir, verifier(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	status, e := s.Status(context.Background(), got.Permit.JobID)
	if e != nil || status.Phase != NeedsIntervention || status.ConsumedAt != got.ConsumedAt || status.Permit != got.Permit {
		t.Fatal(status, e)
	}
	again, e := s.Admit(context.Background(), raw, testNow.Add(24*time.Hour))
	if e != nil || again != status {
		t.Fatal("reopen duplicate", again, e)
	}
	_, e = s.Admit(context.Background(), signed(t, permit(t, 778)), testNow)
	requireErr(t, e, ErrBusy)
	_ = s.Close()
	s, e = Open(context.Background(), dir, verifier(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	again, e = s.Status(context.Background(), got.Permit.JobID)
	if e != nil || again != status {
		t.Fatal("uncertainty was cleared")
	}
}

func TestExpiredSequenceAndClockCannotRevive(t *testing.T) {
	s, dir := fixture(t)
	p := permit(t, 10)
	raw := signed(t, p)
	expiredAt := testNow.Add(time.Minute)
	got, e := s.Admit(context.Background(), raw, expiredAt)
	requireErr(t, e, actionpermit.ErrExpired)
	if got.Phase != Expired {
		t.Fatal(got)
	}
	_, e = s.Admit(context.Background(), signed(t, permit(t, 9)), expiredAt)
	requireErr(t, e, ErrReplay)
	changed := permit(t, 10)
	changed.JobID = "action_" + strings.Repeat("e", 32)
	_, e = s.Admit(context.Background(), signed(t, changed), expiredAt)
	requireErr(t, e, ErrReplay)
	_, e = s.Admit(context.Background(), signed(t, permit(t, 11)), testNow)
	requireErr(t, e, actionpermit.ErrClock)
	_ = s.Close()
	s, e = Open(context.Background(), dir, verifier(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	duplicate, e := s.Admit(context.Background(), raw, testNow)
	if e != nil || duplicate != got {
		t.Fatal("expired record revived", duplicate, e)
	}
	_, e = s.Admit(context.Background(), signed(t, permit(t, 11)), expiredAt.Add(-time.Microsecond))
	requireErr(t, e, actionpermit.ErrClock)
	fresh := permit(t, 50)
	fresh.IssuedAt = expiredAt.Unix()
	fresh.NotBefore = fresh.IssuedAt
	fresh.StartDeadline = fresh.IssuedAt + 60
	got, e = s.Admit(context.Background(), signed(t, fresh), expiredAt)
	if e != nil || got.Phase != Admitted {
		t.Fatal(got, e)
	}
}

func TestPolicyDisableChangesPreserveHistoricalStatusAndFloor(t *testing.T) {
	s, dir := fixture(t)
	p := permit(t, 1)
	raw := signed(t, p)
	got, e := s.Admit(context.Background(), raw, testNow.Add(time.Minute))
	requireErr(t, e, actionpermit.ErrExpired)
	_ = s.Close()
	c := pins()
	c.Enabled = false
	c.RootPolicyDigest = actionpermit.Digest([]byte("revoked new policy"))
	c.Services = []actionpermit.ServiceRule{{Unit: "other.service", UnitPolicyDigest: actionpermit.Digest([]byte("other unit"))}}
	v, e := actionpermit.NewVerifier(c)
	if e != nil {
		t.Fatal(e)
	}
	s, e = Open(context.Background(), dir, v)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	status, e := s.Admit(context.Background(), raw, testNow)
	if e != nil || status != got {
		t.Fatal("revocation lost original status")
	}
	_, e = s.Admit(context.Background(), signed(t, permit(t, 2)), testNow.Add(time.Minute))
	requireErr(t, e, actionpermit.ErrDisabled)
	_ = s.Close()
	c = pins()
	c.IncarnationDigest = actionpermit.Digest([]byte("another incarnation"))
	v, _ = actionpermit.NewVerifier(c)
	_, e = Open(context.Background(), dir, v)
	requireErr(t, e, ErrBinding)
}

func TestInitializeExistingOnlyLockAndClosedCopies(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	v := verifier(t)
	_, e := Open(context.Background(), dir, v)
	requireErr(t, e, ErrCorrupt)
	if _, e = os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("Open created directory")
	}
	s, e := Initialize(context.Background(), dir, v)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_, e = Initialize(context.Background(), dir, v)
	if e == nil {
		t.Fatal("reset allowed")
	}
	_, e = Open(context.Background(), dir, v)
	requireErr(t, e, ErrLocked)
	copyState := *s
	_ = s.Close()
	_, e = copyState.Admit(context.Background(), signed(t, permit(t, 1)), testNow)
	requireErr(t, e, ErrClosed)
	_, e = (State{}).Status(context.Background(), "anything")
	requireErr(t, e, ErrClosed)
	_, e = Initialize(context.Background(), filepath.Join(t.TempDir(), "bad"), actionpermit.Verifier{})
	requireErr(t, e, ErrBinding)
}

func TestConcurrentCopiesConsumeOneRecord(t *testing.T) {
	s, _ := fixture(t)
	copyState := *s
	raw := signed(t, permit(t, 1))
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, e := copyState.Admit(context.Background(), raw, testNow)
			if e != nil || got.Phase != Admitted {
				t.Errorf("duplicate: %v", e)
			}
		}()
	}
	wg.Wait()
	if len(s.inner.record.Jobs) != 1 || s.inner.record.Floor != 1 {
		t.Fatal("duplicate consumption")
	}
}

func TestRejectedPermitsNeverAdvanceState(t *testing.T) {
	s, dir := fixture(t)
	before := read(t, filepath.Join(dir, stateName))
	p := permit(t, 1)
	for _, mutate := range []func(*actionpermit.Permit){
		func(p *actionpermit.Permit) { p.EndpointID = "agent_" + strings.Repeat("a", 32) },
		func(p *actionpermit.Permit) { p.IncarnationDigest = actionpermit.Digest([]byte("new")) },
		func(p *actionpermit.Permit) { p.RootPolicyDigest = actionpermit.Digest([]byte("new")) },
		func(p *actionpermit.Permit) {
			p.Plan.Unit = "other.service"
			p.PlanDigest, _ = actionpermit.PlanDigest(p.Plan)
		},
		func(p *actionpermit.Permit) { p.IssuedAt++; p.NotBefore++ },
	} {
		q := p
		mutate(&q)
		if _, e := s.Admit(context.Background(), signed(t, q), testNow); e == nil {
			t.Fatal("foreign/future accepted")
		}
	}
	for _, raw := range [][]byte{nil, []byte(`{}`), append(signed(t, p), ' ')} {
		if _, e := s.Admit(context.Background(), raw, testNow); e == nil {
			t.Fatal("malformed accepted")
		}
	}
	if !bytes.Equal(before, read(t, filepath.Join(dir, stateName))) {
		t.Fatal("rejection mutated ledger")
	}
	_, e := s.Status(context.Background(), p.JobID)
	requireErr(t, e, ErrNotFound)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e = s.Admit(ctx, signed(t, p), testNow)
	requireErr(t, e, ErrCanceled)
}

func TestCapacityRetainsEveryConsumedSequence(t *testing.T) {
	s, _ := fixture(t)
	for i := 1; i <= MaxJobs; i++ {
		got, e := s.Admit(context.Background(), signed(t, permit(t, uint64(i))), testNow.Add(time.Minute))
		requireErr(t, e, actionpermit.ErrExpired)
		if got.Phase != Expired {
			t.Fatal(got)
		}
	}
	_, e := s.Admit(context.Background(), signed(t, permit(t, MaxJobs+1)), testNow.Add(time.Minute))
	requireErr(t, e, ErrCapacity)
	got, e := s.Admit(context.Background(), signed(t, permit(t, 1)), testNow)
	if e != nil || got.Phase != Expired {
		t.Fatal("old status discarded")
	}
}

func TestRecordStrictnessAndSignatureValidation(t *testing.T) {
	s, _ := fixture(t)
	_, e := s.Admit(context.Background(), signed(t, permit(t, 1)), testNow)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := encodeRecord(s.inner.record)
	if e != nil {
		t.Fatal(e)
	}
	for i, b := range [][]byte{append(bytes.Clone(raw), ' '), bytes.Replace(raw, []byte(`"floor":"1"`), []byte(`"floor":"0"`), 1), bytes.Replace(raw, []byte(`"floor":"1"`), []byte(`"floor":"1","floor":"1"`), 1), bytes.Replace(raw, []byte(`"phase":"admitted"`), []byte(`"phase":"succeeded"`), 1)} {
		if _, e := decodeRecord(b, verifier(t)); e == nil {
			t.Fatalf("bad record %d", i)
		}
	}
	r := s.inner.record
	r.Jobs = append([]diskJob(nil), r.Jobs...)
	r.Jobs[0].Envelope = bytes.Clone(r.Jobs[0].Envelope)
	r.Jobs[0].Envelope[len(r.Jobs[0].Envelope)-4] ^= 1
	b, _ := encodeRecord(r)
	if _, e := decodeRecord(b, verifier(t)); e == nil {
		t.Fatal("invalid signature persisted")
	}
}
