package operatorauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
	"testing"
)

func singleAccountWorkFixture(t *testing.T) (*Manager, *memoryAccounts, Session) {
	t.Helper()
	_, store, _, _ := accountFixture(t)
	store.snapshot.Accounts = store.snapshot.Accounts[:1]
	m, err := New(Config{AuthorityStore: store, AuthorityID: store.snapshot.AuthorityID, AuthorityProfile: store.snapshot.Profile})
	if err != nil {
		t.Fatal(err)
	}
	return m, store, seedLiveSession(m, "admin", 1)
}
func TestSingleLiveAccountCannotChangeWorkFactors(t *testing.T) {
	for _, factors := range []string{"m=131072,t=2,p=1", "m=65536,t=3,p=1", "m=65536,t=2,p=2"} {
		t.Run(factors, func(t *testing.T) {
			m, store, admin := singleAccountWorkFixture(t)
			changed := strings.Replace(fixtureHash(), "m=65536,t=2,p=1", factors, 1)
			if _, err := parseHash(changed); err != nil {
				t.Fatal("fixture must be an otherwise allowed verifier")
			}
			err := m.ChangeAccount(context.Background(), admin, AccountChange{TargetID: admin.ActorID(), ExpectedRevision: 1, Capabilities: []Capability{Read, ManageAccounts}, PasswordHash: changed})
			if !errors.Is(err, ErrConfiguration) {
				t.Fatal("single-account work-factor change was admitted")
			}
			if store.snapshot.Revision != 1 || len(store.audits) != 0 || admin.Lifetime().Err() != nil || m.live.byName["admin"].pending.Load() {
				t.Fatal("rejected work policy changed authority or revoked requester")
			}
		})
	}
}
func TestSingleLiveAccountSameWorkPasswordResetAndRestart(t *testing.T) {
	m, store, admin := singleAccountWorkFixture(t)
	const password = "synthetic-rotated-fixture-password"
	salt := []byte("rotated-fixture-salt")
	hash := argon2.IDKey([]byte(password), salt, 2, 65536, 1, 32)
	encoded := fmt.Sprintf("$argon2id$v=19$m=65536,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash))
	if err := m.ChangeAccount(context.Background(), admin, AccountChange{TargetID: admin.ActorID(), ExpectedRevision: 1, Capabilities: []Capability{Read, ManageAccounts}, PasswordHash: encoded}); err != nil {
		t.Fatal(err)
	}
	if admin.Lifetime().Err() == nil || len(store.audits) != 1 {
		t.Fatal("reset did not revoke and audit")
	}
	fresh, err := New(Config{AuthorityStore: store, AuthorityID: store.snapshot.AuthorityID, AuthorityProfile: store.snapshot.Profile})
	if err != nil {
		t.Fatal(err)
	}
	for _, current := range []*Manager{m, fresh} {
		v := current.live.byName["admin"].current.Load().principal.verifier
		if current.verifier.memory != v.memory || current.verifier.iterations != v.iterations || current.verifier.parallelism != v.parallelism {
			t.Fatal("known and dummy workload policy diverged")
		}
		if _, err := current.LoginNamed(context.Background(), "127.0.0.1", "admin", password); err != nil {
			t.Fatal("new verifier rejected", err)
		}
	}
}
