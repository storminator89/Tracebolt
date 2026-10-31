package operatorauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func fairnessManager(t *testing.T, n int, now func() time.Time) *Manager {
	t.Helper()
	ops := make([]Operator, n)
	for i := range ops {
		ops[i] = Operator{ID: fmt.Sprintf("operator_%032x", i+1), Username: fmt.Sprintf("actor%d", i+1), PasswordHash: fixtureHash(), Capabilities: []Capability{Read}}
	}
	ops[0].Capabilities = append(ops[0].Capabilities, ManageSessions)
	m, err := New(Config{Operators: ops, Now: now})
	if err != nil {
		t.Fatal("fairness fixture configuration rejected")
	}
	return m
}

// Seed all but one session without repeating expensive password verification;
// the real LoginNamed path tests final admission under the exact same lock.
func seedActorSession(m *Manager, actor int, ordinal int) Session {
	id := fmt.Sprintf("%032x", actor*100+ordinal)
	principal := m.operators[fmt.Sprintf("actor%d", actor)]
	principal.verifier = verifier{}
	ctx, cancel := context.WithCancel(context.Background())
	s := Session{ID: id, CSRFToken: "fixture-csrf-never-export", actor: principal, ExpiresAt: m.now().Add(DefaultTTL), lifetime: ctx, revoke: cancel, gate: &sessionGate{now: m.now, expires: m.now().Add(DefaultTTL)}}
	m.sessions[sha256.Sum256([]byte(id))] = s
	return s
}

func TestNamedSessionActorCeilingAndFirstSlotReserve(t *testing.T) {
	m := fairnessManager(t, 2, nil)
	for i := 1; i <= MaxSessionsPerActor; i++ {
		seedActorSession(m, 1, i)
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "actor1", fixturePassword); !errors.Is(err, ErrCapacity) {
		t.Fatal("one actor exceeded its ceiling")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.2", "actor2", fixturePassword); err != nil {
		t.Fatal("one actor denied another account's first session")
	}
	m = fairnessManager(t, MaxOperators, nil)
	for actor := 1; actor < MaxOperators; actor++ {
		seedActorSession(m, actor, 1)
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "actor1", fixturePassword); !errors.Is(err, ErrCapacity) {
		t.Fatal("represented account consumed the global first-session reserve")
	}
	last, err := m.LoginNamed(context.Background(), "127.0.0.2", "actor32", fixturePassword)
	if err != nil || last.ActorID() != m.operators["actor32"].id || len(m.sessions) != MaxSessions {
		t.Fatal("reserved first session could not enter at global capacity")
	}
}

func TestGlobalFirstSessionReserveAlsoBoundsRepeatedSessions(t *testing.T) {
	m := fairnessManager(t, 8, nil)
	for actor := 1; actor <= 8; actor++ {
		count := MaxSessionsPerActor
		if actor == 8 {
			count--
		}
		for ordinal := 1; ordinal <= count; ordinal++ {
			seedActorSession(m, actor, ordinal)
		}
	}
	if len(m.sessions) != MaxSessions-FirstSessionReserve {
		t.Fatal("invalid reserve fixture")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "actor8", fixturePassword); !errors.Is(err, ErrCapacity) {
		t.Fatal("repeat login consumed fixed global first-session reserve")
	}
}

func TestConfiguredAbsentActorsReserveBeforeExhaustion(t *testing.T) {
	m := fairnessManager(t, 30, nil)
	seedActorSession(m, 1, 1)
	seedActorSession(m, 1, 2)
	seedActorSession(m, 1, 3)
	if m.sessionAvailableLocked(m.operators["actor1"].id) {
		t.Fatal("absent configured accounts' reserved slots were consumed")
	}
	if !m.sessionAvailableLocked(m.operators["actor30"].id) {
		t.Fatal("new actor could not use its reserved slot")
	}
}

func TestSessionViewsAreBoundedAccountScopedAndSecretFree(t *testing.T) {
	m := fairnessManager(t, 3, nil)
	admin := seedActorSession(m, 1, 1)
	reader := seedActorSession(m, 2, 1)
	other := seedActorSession(m, 3, 1)
	view, err := m.Sessions(context.Background(), reader)
	if err != nil || len(view.Items) != 1 || !view.Items[0].Current || view.CanManageAll || view.PerActorLimit != MaxSessionsPerActor || view.GlobalLimit != MaxSessions || view.FirstSessionReserve != FirstSessionReserve {
		t.Fatal("account-scoped session view is incorrect")
	}
	raw, _ := json.Marshal(view)
	for _, secret := range []string{reader.CSRFToken, fixtureHash(), other.ActorID(), other.ID, "actor2", "127.0.0.1"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("account session view disclosed credential or unrelated identity")
		}
	}
	all, err := m.Sessions(context.Background(), admin)
	if err != nil || !all.CanManageAll || len(all.Items) != 3 {
		t.Fatal("explicit session administrator did not receive bounded view")
	}
	foreign := fairnessManager(t, 3, nil)
	if _, err := foreign.Sessions(context.Background(), reader); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("session from another manager admitted")
	}
	reader.actor.grants |= capabilityBit(ManageSessions) // Private in-package adversarial fixture.
	reader.ID = "ffffffffffffffffffffffffffffffff"
	if _, err := m.Sessions(context.Background(), reader); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("modified requester admitted")
	}
}

func TestSessionRevocationScopeAndSelfRevocation(t *testing.T) {
	m := fairnessManager(t, 3, nil)
	admin := seedActorSession(m, 1, 1)
	reader := seedActorSession(m, 2, 1)
	other := seedActorSession(m, 3, 1)
	for _, id := range []string{other.ID, strings.Repeat("f", 32)} {
		if revoked, err := m.RevokeSession(context.Background(), reader, id); err != nil || revoked {
			t.Fatal("reader revoked unrelated session or learned its existence")
		}
	}
	if other.gate.revoked.Load() {
		t.Fatal("denied revocation changed target")
	}
	if revoked, err := m.RevokeSession(context.Background(), admin, other.ID); err != nil || !revoked {
		t.Fatal("explicit administrator could not revoke")
	}
	if _, err := other.BeginCapability(context.Background(), Read); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("copied target session retained authority")
	}
	if revoked, err := m.RevokeSession(context.Background(), reader, reader.ID); err != nil || !revoked {
		t.Fatal("self revocation failed")
	}
	if _, err := m.Sessions(context.Background(), reader); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("self-revoked session remained usable")
	}
}

func TestSessionRevocationDrainsMutationAndConcurrentRevokers(t *testing.T) {
	m := fairnessManager(t, 2, nil)
	admin := seedActorSession(m, 1, 1)
	target := seedActorSession(m, 2, 1)
	release, err := target.BeginCapability(context.Background(), Read)
	if err != nil {
		t.Fatal("fixture admission failed")
	}
	done := make(chan error, 2)
	go func() { _, err := m.RevokeSession(context.Background(), admin, target.ID); done <- err }()
	select {
	case <-target.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not mark/cancel target")
	}
	go func() { _, err := m.RevokeSession(context.Background(), admin, target.ID); done <- err }()
	select {
	case <-done:
		t.Fatal("revocation returned before admitted work drained")
	case <-time.After(20 * time.Millisecond):
	}
	release()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("concurrent revoker failed")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("revocation did not drain")
		}
	}
}

func TestExpiryReleasesActorAndGlobalCapacityWithoutExtendingTimeout(t *testing.T) {
	now := time.Now()
	m := fairnessManager(t, 2, func() time.Time { return now })
	for i := 1; i <= MaxSessionsPerActor; i++ {
		seedActorSession(m, 1, i)
	}
	now = now.Add(DefaultTTL)
	s, err := m.LoginNamed(context.Background(), "127.0.0.1", "actor1", fixturePassword)
	if err != nil || len(m.sessions) != 1 || !s.ExpiresAt.Equal(now.Add(DefaultTTL)) {
		t.Fatal("expired sessions retained capacity or timeout changed")
	}
	for _, id := range []string{"", " " + s.ID, strings.ToUpper(s.ID) + "X", strings.Repeat("0", 33)} {
		if _, err := m.RevokeSession(context.Background(), s, id); !errors.Is(err, ErrConfiguration) {
			t.Fatal("noncanonical session selector accepted")
		}
	}
}

func TestGlobalFallbackReserveWith31RepresentedActors(t *testing.T) {
	m := fairnessManager(t, MaxOperators-1, nil)
	for actor := 1; actor < MaxOperators; actor++ {
		seedActorSession(m, actor, 1)
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "actor1", fixturePassword); !errors.Is(err, ErrCapacity) {
		t.Fatal("represented actor consumed fallback first-session reserve")
	}
	if len(m.sessions) != MaxSessions-FirstSessionReserve {
		t.Fatal("denied login changed retained capacity")
	}
}

func TestExpiredAdmittedMutationRetainsActorQuotaUntilDrain(t *testing.T) {
	now := time.Now()
	m := fairnessManager(t, 2, func() time.Time { return now })
	target := seedActorSession(m, 2, 1)
	for ordinal := 2; ordinal <= MaxSessionsPerActor; ordinal++ {
		s := seedActorSession(m, 2, ordinal)
		s.ExpiresAt = now.Add(2 * DefaultTTL)
		s.gate.expires = s.ExpiresAt
		m.sessions[sha256.Sum256([]byte(s.ID))] = s
	}
	release, err := target.BeginCapability(context.Background(), Read)
	if err != nil {
		t.Fatal("fixture admission failed")
	}
	defer release()
	now = now.Add(DefaultTTL)
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "actor2", fixturePassword); !errors.Is(err, ErrCapacity) {
		t.Fatal("expired tombstone stopped counting before admitted work drained")
	}
	select {
	case <-target.Lifetime().Done():
	default:
		t.Fatal("expiry cleanup did not cancel target lifetime")
	}
	if len(m.sessions) != MaxSessionsPerActor {
		t.Fatal("expiry discarded an in-flight tombstone")
	}
	release()
	if _, err := m.LoginNamed(context.Background(), "127.0.0.2", "actor2", fixturePassword); err != nil || len(m.sessions) != MaxSessionsPerActor {
		t.Fatal("expiry capacity did not recover after drain")
	}
}

func TestRevokedAdmittedMutationRetainsActorQuotaUntilDrain(t *testing.T) {
	m := fairnessManager(t, 2, nil)
	admin := seedActorSession(m, 1, 1)
	target := seedActorSession(m, 2, 1)
	for ordinal := 2; ordinal <= MaxSessionsPerActor; ordinal++ {
		seedActorSession(m, 2, ordinal)
	}
	release, err := target.BeginCapability(context.Background(), Read)
	if err != nil {
		t.Fatal("fixture admission failed")
	}
	defer release()
	done := make(chan error, 1)
	go func() { _, err := m.RevokeSession(context.Background(), admin, target.ID); done <- err }()
	select {
	case <-target.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not mark target")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.1", "actor2", fixturePassword); !errors.Is(err, ErrCapacity) {
		t.Fatal("revoked tombstone stopped counting before admitted work drained")
	}
	select {
	case <-done:
		t.Fatal("revocation returned before admitted work drained")
	default:
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("revocation failed after drain")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revocation did not finish after drain")
	}
	if _, err := m.LoginNamed(context.Background(), "127.0.0.2", "actor2", fixturePassword); err != nil || len(m.sessions) != 1+MaxSessionsPerActor {
		t.Fatal("revoked session capacity did not recover after drain")
	}
}
