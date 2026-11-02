package operatorauth

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func testFactorSecret(b byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(strings.Repeat(string(b), 32)))
}
func TestMFARFC6238SHA256Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890123456789012"))
	for _, tc := range []struct {
		unix int64
		want string
	}{{59, "46119246"}, {1111111109, "68084774"}, {1111111111, "67062674"}, {1234567890, "91819424"}, {2000000000, "90698825"}, {20000000000, "77737706"}} {
		got, ok := factorCode(secret, uint64(tc.unix/30))
		if !ok || got != tc.want {
			t.Fatalf("time %d got %s want %s", tc.unix, got, tc.want)
		}
	}
	for _, secret := range []string{"", strings.ToLower(secret), secret + "=", testFactorSecret('a')[:51] + "Z"} {
		if raw, ok := factorSecret(secret); ok {
			clear(raw)
			t.Fatal("noncanonical secret accepted")
		}
	}
}

type factorMemory struct {
	*memoryAccounts
	proposal string
}

func (s *factorMemory) ReadFactorProposal(context.Context, string, uint64) (string, error) {
	return s.proposal, nil
}

type factorClock struct {
	sync.Mutex
	at time.Time
}

func (c *factorClock) now() time.Time          { c.Lock(); defer c.Unlock(); return c.at }
func (c *factorClock) advance(d time.Duration) { c.Lock(); c.at = c.at.Add(d); c.Unlock() }
func factorFixture(t *testing.T) (*Manager, *factorMemory, *factorClock) {
	t.Helper()
	_, base, _, _ := accountFixture(t)
	for i := range base.snapshot.Accounts {
		base.snapshot.Accounts[i].Factor = &AccountFactor{Version: FactorVersion, Generation: 1, State: FactorActive, Secret: testFactorSecret(byte('a' + i))}
	}
	store := &factorMemory{memoryAccounts: base, proposal: testFactorSecret('c')}
	clock := &factorClock{at: time.Unix(1800000000, 0)}
	m, e := New(Config{AuthorityID: base.snapshot.AuthorityID, AuthorityProfile: "tls", AuthorityStore: store, Now: clock.now})
	if e != nil {
		t.Fatal(e)
	}
	return m, store, clock
}
func otpAt(secret string, c *factorClock) string {
	code, _ := factorCode(secret, uint64(c.now().Unix()/30))
	return code
}
func TestMFALoginRequiresFactorAndConsumesWithoutEpochChange(t *testing.T) {
	m, s, c := factorFixture(t)
	ctx := context.Background()
	secret := testFactorSecret('a')
	if _, e := m.LoginNamed(ctx, "127.0.0.1", "admin", fixturePassword); !errors.Is(e, ErrCredentials) {
		t.Fatal("password-only", e)
	}
	if _, e := m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, "00000000"); !errors.Is(e, ErrCredentials) {
		t.Fatal("wrong otp", e)
	}
	first, e := m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, otpAt(secret, c))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, otpAt(secret, c)); !errors.Is(e, ErrCredentials) {
		t.Fatal("replay", e)
	}
	c.advance(time.Minute)
	if _, e = m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, otpAt(secret, c)); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Lookup(first.Token); e != nil {
		t.Fatal("another login revoked prior session", e)
	}
	snap, _ := s.Load(ctx)
	if snap.Revision != 3 || snap.Accounts[0].Revision != 1 || snap.Accounts[0].RevocationFloor != 0 {
		t.Fatal("OTP consumption changed authority epoch")
	}
	if len(s.audits) != 2 || s.audits[0].Operation != "factor_use" || s.audits[0].Current != s.audits[0].Previous {
		t.Fatal("missing factor audit")
	}
}
func TestMFAConcurrentReplayExactlyOneLogin(t *testing.T) {
	m, _, c := factorFixture(t)
	ctx := context.Background()
	code := otpAt(testFactorSecret('a'), c)
	start := make(chan struct{})
	out := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; _, e := m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, code); out <- e }()
	}
	close(start)
	successes := 0
	for i := 0; i < 2; i++ {
		if e := <-out; e == nil {
			successes++
		} else if !errors.Is(e, ErrCredentials) && !errors.Is(e, ErrBusy) {
			t.Fatal(e)
		}
	}
	if successes != 1 {
		t.Fatal("OTP admitted more/less than once", successes)
	}
}
func TestMFAResetAndReenrollmentRetireSessionsAndEpoch(t *testing.T) {
	m, s, c := factorFixture(t)
	ctx := context.Background()
	admin, e := m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, otpAt(testFactorSecret('a'), c))
	if e != nil {
		t.Fatal(e)
	}
	worker, e := m.LoginNamedMFA(ctx, "127.0.0.2", "worker", fixturePassword, otpAt(testFactorSecret('b'), c))
	if e != nil {
		t.Fatal(e)
	}
	c.advance(time.Minute)
	if e = m.ResetFactor(ctx, admin, "127.0.0.1", worker.ActorID(), 1, "wrong-password", otpAt(testFactorSecret('a'), c)); !errors.Is(e, ErrCredentials) {
		t.Fatal("wrong password reset", e)
	}
	if e = m.ResetFactor(ctx, admin, "127.0.0.1", worker.ActorID(), 1, fixturePassword, otpAt(testFactorSecret('b'), c)); !errors.Is(e, ErrCredentials) {
		t.Fatal("target factor substituted", e)
	}
	if e = m.ResetFactor(ctx, admin, "127.0.0.1", worker.ActorID(), 1, fixturePassword, otpAt(testFactorSecret('a'), c)); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Lookup(worker.Token); e == nil {
		t.Fatal("old target session survived")
	}
	if _, e = m.Lookup(admin.Token); e != nil {
		t.Fatal("unrelated admin revoked", e)
	}
	if r, e := m.BeginActorAdmission(ctx, worker.ActorID(), 1, RestartService); e == nil {
		r()
		t.Fatal("old epoch survived")
	}
	if _, e = m.LoginNamedMFA(ctx, "127.0.0.2", "worker", fixturePassword, otpAt(testFactorSecret('b'), c)); !errors.Is(e, ErrCredentials) {
		t.Fatal("old factor survived", e)
	}
	if _, e = m.LoginNamed(ctx, "127.0.0.2", "worker", fixturePassword); !errors.Is(e, ErrCredentials) {
		t.Fatal("pending factor downgraded", e)
	}
	if e = m.EnrollFactor(ctx, "127.0.0.2", "worker", fixturePassword, otpAt(s.proposal, c), 2); e != nil {
		t.Fatal(e)
	}
	if _, e = m.LoginNamedMFA(ctx, "127.0.0.3", "worker", fixturePassword, otpAt(s.proposal, c)); !errors.Is(e, ErrCredentials) {
		t.Fatal("enrollment proof replayed", e)
	}
	c.advance(time.Minute)
	fresh, e := m.LoginNamedMFA(ctx, "127.0.0.3", "worker", fixturePassword, otpAt(s.proposal, c))
	if e != nil {
		t.Fatal(e)
	}
	if fresh.ApprovalEpoch() != 3 {
		t.Fatal("wrong re-enrollment epoch")
	}
	snap, _ := s.Load(ctx)
	if snap.Accounts[1].Factor.Generation != 2 || snap.Accounts[1].Factor.State != FactorActive {
		t.Fatal("wrong factor generation")
	}
}
func TestMFAUncertainConsumptionFencesAccount(t *testing.T) {
	m, s, c := factorFixture(t)
	ctx := context.Background()
	old := seedLiveSession(m, "admin", 10)
	other := seedLiveSession(m, "worker", 11)
	s.fail = true
	if _, e := m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, otpAt(testFactorSecret('a'), c)); !errors.Is(e, ErrAuthorityUncertain) {
		t.Fatal(e)
	}
	if _, e := m.Lookup(old.Token); e == nil {
		t.Fatal("uncertain account live")
	}
	if _, e := m.Lookup(other.Token); e != nil {
		t.Fatal("other account fenced", e)
	}
	s.fail = false
	c.advance(time.Minute)
	if _, e := m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, otpAt(testFactorSecret('a'), c)); e == nil {
		t.Fatal("uncertainty silently retried")
	}
}
func TestMFAResetCannotRemoveLastUsableAdministrator(t *testing.T) {
	m, _, c := factorFixture(t)
	ctx := context.Background()
	a, e := m.LoginNamedMFA(ctx, "127.0.0.1", "admin", fixturePassword, otpAt(testFactorSecret('a'), c))
	if e != nil {
		t.Fatal(e)
	}
	c.advance(time.Minute)
	if e = m.ResetFactor(ctx, a, "127.0.0.1", a.ActorID(), 1, fixturePassword, otpAt(testFactorSecret('a'), c)); !errors.Is(e, ErrConfiguration) {
		t.Fatal("last admin reset", e)
	}
	if _, e = m.Lookup(a.Token); e != nil {
		t.Fatal("rejected reset revoked administrator", e)
	}
}

func TestMFARetiredSecretCannotBeEnrolledAgain(t *testing.T) {
	m, s, c := factorFixture(t)
	ctx := context.Background()
	admin := seedLiveSession(m, "admin", 21)
	worker := seedLiveSession(m, "worker", 22)
	if e := m.ResetFactor(ctx, admin, "127.0.0.1", worker.ActorID(), 1, fixturePassword, otpAt(testFactorSecret('a'), c)); e != nil {
		t.Fatal(e)
	}
	s.proposal = testFactorSecret('b')
	if e := m.EnrollFactor(ctx, "127.0.0.2", "worker", fixturePassword, otpAt(s.proposal, c), 2); !errors.Is(e, ErrCredentials) {
		t.Fatal("retired factor reintroduced", e)
	}
	snapshot, _ := s.Load(ctx)
	if snapshot.Accounts[1].Factor.Generation != 2 || len(snapshot.Accounts[1].Factor.RetiredHashes) != 1 {
		t.Fatal("retired history absent")
	}
	cloned := copySnapshot(snapshot)
	cloned.Accounts[1].Factor.RetiredHashes[0] = "changed"
	if snapshot.Accounts[1].Factor.RetiredHashes[0] == "changed" {
		t.Fatal("history alias")
	}
	// Reopening from the persisted snapshot cannot forget factor use or retirement.
	reopened, e := New(Config{AuthorityID: snapshot.AuthorityID, AuthorityProfile: "tls", AuthorityStore: s, Now: c.now})
	if e != nil {
		t.Fatal(e)
	}
	if e = reopened.EnrollFactor(ctx, "127.0.0.3", "worker", fixturePassword, otpAt(s.proposal, c), 2); !errors.Is(e, ErrCredentials) {
		t.Fatal("restart lost retired history", e)
	}
	if _, e = reopened.LoginNamedMFA(ctx, "127.0.0.4", "admin", fixturePassword, otpAt(testFactorSecret('a'), c)); !errors.Is(e, ErrCredentials) {
		t.Fatal("restart replayed admin proof", e)
	}
}
func TestMFAStaleResetRevisionConsumesProofWithoutChangingTarget(t *testing.T) {
	m, s, c := factorFixture(t)
	ctx := context.Background()
	admin := seedLiveSession(m, "admin", 31)
	worker := seedLiveSession(m, "worker", 32)
	code := otpAt(testFactorSecret('a'), c)
	if e := m.ResetFactor(ctx, admin, "127.0.0.1", worker.ActorID(), 99, fixturePassword, code); !errors.Is(e, ErrAccountConflict) {
		t.Fatal(e)
	}
	if e := m.ResetFactor(ctx, admin, "127.0.0.1", worker.ActorID(), 1, fixturePassword, code); !errors.Is(e, ErrCredentials) {
		t.Fatal("one-use proof replayed", e)
	}
	if _, e := m.Lookup(worker.Token); e != nil {
		t.Fatal("stale reset invalidated target", e)
	}
	snap, _ := s.Load(ctx)
	if snap.Accounts[1].Revision != 1 || snap.Accounts[1].Factor.State != FactorActive {
		t.Fatal("stale reset changed target")
	}
}
func TestMFAInitialEnrollmentAndInvalidProposal(t *testing.T) {
	_, base, _, _ := accountFixture(t)
	ctx := context.Background()
	clock := &factorClock{at: time.Unix(1800000000, 0)}
	s := &factorMemory{memoryAccounts: base, proposal: "bad"}
	m, e := New(Config{AuthorityID: base.snapshot.AuthorityID, AuthorityProfile: "tls", AuthorityStore: s, Now: clock.now})
	if e != nil {
		t.Fatal(e)
	}
	old, e := m.LoginNamed(ctx, "127.0.0.1", "worker", fixturePassword)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.EnrollFactor(ctx, "127.0.0.2", "worker", fixturePassword, "00000000", 1); !errors.Is(e, ErrCredentials) {
		t.Fatal("invalid proposal accepted", e)
	}
	s.proposal = testFactorSecret('d')
	if e = m.EnrollFactor(ctx, "127.0.0.2", "worker", fixturePassword, otpAt(s.proposal, clock), 1); e != nil {
		t.Fatal(e)
	}
	if _, e = m.Lookup(old.Token); e == nil {
		t.Fatal("pre-enrollment session survived")
	}
	if _, e = m.LoginNamed(ctx, "127.0.0.1", "worker", fixturePassword); !errors.Is(e, ErrCredentials) {
		t.Fatal("new factor bypassed", e)
	}
}

func TestMFAFreshProofExpiresWhileActorAdmissionDrains(t *testing.T) {
	for _, operation := range []string{"reset", "enroll"} {
		t.Run(operation, func(t *testing.T) {
			m, s, c := factorFixture(t)
			ctx := context.Background()
			if operation == "enroll" {
				// Initial enrollment on a password-only account uses the same drain fence.
				s.snapshot.Accounts[1].Factor = nil
				var e error
				m, e = New(Config{AuthorityID: s.snapshot.AuthorityID, AuthorityProfile: "tls", AuthorityStore: s, Now: c.now})
				if e != nil {
					t.Fatal(e)
				}
			}
			admin := seedLiveSession(m, "admin", 41)
			worker := seedLiveSession(m, "worker", 42)
			hold, e := m.BeginActorAdmission(ctx, worker.ActorID(), 1, RestartService)
			if e != nil {
				t.Fatal(e)
			}
			defer hold()
			done := make(chan error, 1)
			go func() {
				if operation == "reset" {
					done <- m.ResetFactor(ctx, admin, "127.0.0.1", worker.ActorID(), 1, fixturePassword, otpAt(testFactorSecret('a'), c))
				} else {
					done <- m.EnrollFactor(ctx, "127.0.0.1", "worker", fixturePassword, otpAt(s.proposal, c), 1)
				}
			}()
			select {
			case <-worker.Lifetime().Done():
			case <-time.After(5 * time.Second):
				t.Fatal("factor transition never reached drain")
			}
			c.advance(2 * time.Minute)
			hold()
			if e := awaitAccount(t, done); !errors.Is(e, ErrAuthorityUncertain) {
				t.Fatal("expired proof committed", e)
			}
			snap, _ := s.Load(ctx)
			if snap.Accounts[1].Revision != 1 {
				t.Fatal("stale proof changed target")
			}
			if !m.live.byName["worker"].pending.Load() {
				t.Fatal("uncertain target silently unfenced")
			}
		})
	}
}

func TestMFAFactorKeysCannotBeSharedOrMovedAcrossAccounts(t *testing.T) {
	_, s, c := factorFixture(t)
	ctx := context.Background()
	snap, _ := s.Load(ctx)
	snap.Accounts[1].Factor.Secret = snap.Accounts[0].Factor.Secret
	if _, e := validateAccounts(snap); !errors.Is(e, ErrConfiguration) {
		t.Fatal("two accounts share active factor", e)
	}
	snap, _ = s.Load(ctx)
	digest, _ := factorSecretDigest(snap.Accounts[1].Factor.Secret)
	snap.Accounts[0].Factor.RetiredHashes = []string{digest}
	snap.Accounts[0].Factor.Generation = 2
	if _, e := validateAccounts(snap); !errors.Is(e, ErrConfiguration) {
		t.Fatal("retired factor active on another account", e)
	}
	// A protected but duplicated enrollment proposal must not change authority.
	s.snapshot.Accounts[1].Factor = nil
	s.proposal = testFactorSecret('a')
	m, e := New(Config{AuthorityID: s.snapshot.AuthorityID, AuthorityProfile: "tls", AuthorityStore: s, Now: c.now})
	if e != nil {
		t.Fatal(e)
	}
	if e = m.EnrollFactor(ctx, "127.0.0.1", "worker", fixturePassword, otpAt(s.proposal, c), 1); !errors.Is(e, ErrConfiguration) {
		t.Fatal("duplicate enrollment accepted", e)
	}
	if m.live.byName["worker"].pending.Load() {
		t.Fatal("invalid proposal fenced unrelated account")
	}
}

func TestMFAProtectedSecretNeverUsesGenericJSONOrFormatting(t *testing.T) {
	_, store, _ := factorFixture(t)
	snapshot, _ := store.Load(context.Background())
	secret := snapshot.Accounts[0].Factor.Secret
	for _, value := range []any{*snapshot.Accounts[0].Factor, snapshot.Accounts[0], snapshot} {
		raw, err := json.Marshal(value)
		if err != nil || strings.Contains(string(raw), secret) || strings.Contains(string(raw), `"secret"`) {
			t.Fatal("factor secret escaped generic JSON", err)
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), secret) {
				t.Fatal("factor secret escaped formatting")
			}
		}
	}
}
func TestMFAFullAccountDoesNotSpendDurableOTP(t *testing.T) {
	m, store, clock := factorFixture(t)
	for n := 1; n <= MaxSessionsPerActor; n++ {
		seedLiveSession(m, "admin", 100+n)
	}
	before, _ := store.Load(context.Background())
	code := otpAt(testFactorSecret('a'), clock)
	if _, err := m.LoginNamedMFA(context.Background(), "127.0.0.1", "admin", fixturePassword, code); !errors.Is(err, ErrCapacity) {
		t.Fatal("full account admitted", err)
	}
	after, _ := store.Load(context.Background())
	if after.Revision != before.Revision || after.Accounts[0].Factor.LastStep != before.Accounts[0].Factor.LastStep || len(store.audits) != 0 {
		t.Fatal("capacity rejection consumed durable OTP")
	}
	// Removing one session proves the same still-current OTP was not burned.
	m.Logout(fmt.Sprintf("%064x", 101))
	if _, err := m.LoginNamedMFA(context.Background(), "127.0.0.1", "admin", fixturePassword, code); err != nil {
		t.Fatal("unspent OTP rejected after slot freed", err)
	}
}

func TestMFAFactorStepBoundsRejectCorruptionAndClockOverflow(t *testing.T) {
	m, s, c := factorFixture(t)
	snapshot, _ := s.Load(context.Background())
	snapshot.Accounts[0].Factor.LastStep = math.MaxUint64
	if _, err := validateAccounts(snapshot); !errors.Is(err, ErrConfiguration) {
		t.Fatal("overflow factor counted as usable administrator", err)
	}
	factor := &AccountFactor{Version: FactorVersion, Generation: 1, State: FactorActive, Secret: testFactorSecret('a')}
	for _, unix := range []int64{math.MaxInt64, int64(maxFactorStep) * 30} {
		code, _ := factorCode(factor.Secret, uint64(unix/30))
		if _, ok := matchFactor(factor, code, unix); ok {
			t.Fatal("overflow clock admitted factor")
		}
	}
	tooFar, cancelFar := m.factorProofContext(context.Background(), maxFactorStep)
	defer cancelFar()
	if tooFar.Err() == nil {
		t.Fatal("distant step overflowed timeout duration")
	}
	guarded, cancel := m.factorProofContext(context.Background(), math.MaxUint64)
	defer cancel()
	if guarded.Err() == nil {
		t.Fatal("overflow step produced usable proof context")
	}
	c.Lock()
	c.at = time.Unix(math.MaxInt64, 0)
	c.Unlock()
	guardedClock, cancelClock := m.factorProofContext(context.Background(), 1)
	defer cancelClock()
	if guardedClock.Err() == nil {
		t.Fatal("overflow clock produced usable proof context")
	}
}
