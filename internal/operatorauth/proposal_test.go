package operatorauth

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type proposalAccounts struct {
	*memoryAccounts
	read func(context.Context, string, uint64) (string, error)
}

func (s *proposalAccounts) ReadCredentialProposal(ctx context.Context, actor string, revision uint64) (string, error) {
	return s.read(ctx, actor, revision)
}
func proposalFixture(t *testing.T, read func(context.Context, string, uint64) (string, error)) (*Manager, *proposalAccounts, Session, Session) {
	t.Helper()
	_, base, _, _ := accountFixture(t)
	store := &proposalAccounts{base, read}
	m, err := New(Config{AuthorityStore: store, AuthorityID: base.snapshot.AuthorityID, AuthorityProfile: base.snapshot.Profile})
	if err != nil {
		t.Fatal(err)
	}
	return m, store, seedLiveSession(m, "admin", 1), seedLiveSession(m, "worker", 2)
}
func TestCredentialProposalPreservesActionableErrors(t *testing.T) {
	for _, want := range []error{ErrAccountConflict, ErrAuthorityUncertain, ErrConfiguration} {
		t.Run(want.Error(), func(t *testing.T) {
			m, s, a, w := proposalFixture(t, func(context.Context, string, uint64) (string, error) { return "", fmt.Errorf("store detail: %w", want) })
			if got := m.ChangeAccountWithCredentialProposal(context.Background(), a, changeFor(w)); !errors.Is(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			if len(s.audits) != 0 || w.Lifetime().Err() != nil {
				t.Fatal("failed proposal changed authority")
			}
		})
	}
}
func TestCredentialProposalRejectsMalformedVerifier(t *testing.T) {
	for _, hash := range []string{"", "invalid"} {
		t.Run(fmt.Sprintf("length%d", len(hash)), func(t *testing.T) {
			m, s, a, w := proposalFixture(t, func(context.Context, string, uint64) (string, error) { return hash, nil })
			if got := m.ChangeAccountWithCredentialProposal(context.Background(), a, changeFor(w)); !errors.Is(got, ErrConfiguration) {
				t.Fatalf("invalid proposal accepted: %v", got)
			}
			if len(s.audits) != 0 || w.Lifetime().Err() != nil {
				t.Fatal("invalid proposal changed authority")
			}
		})
	}
}
func TestCredentialProposalRejectsAlreadyRevokedRequester(t *testing.T) {
	m, s, a, w := proposalFixture(t, func(context.Context, string, uint64) (string, error) {
		t.Error("revoked requester read proposal")
		return fixtureHash(), nil
	})
	m.Logout(a.Token)
	if got := m.ChangeAccountWithCredentialProposal(context.Background(), a, changeFor(w)); !errors.Is(got, ErrUnauthenticated) {
		t.Fatalf("got %v", got)
	}
	if len(s.audits) != 0 {
		t.Fatal("revoked requester committed")
	}
}
func TestCredentialProposalRechecksRequesterAfterRead(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	m, s, a, w := proposalFixture(t, func(context.Context, string, uint64) (string, error) {
		close(entered)
		<-proceed
		return fixtureHash(), nil
	})
	done := make(chan error, 1)
	go func() { done <- m.ChangeAccountWithCredentialProposal(context.Background(), a, changeFor(w)) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("read did not begin")
	}
	logout := make(chan struct{})
	go func() { m.Logout(a.Token); close(logout) }()
	select {
	case <-a.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not fence requester")
	}
	close(proceed)
	if got := awaitAccount(t, done); !errors.Is(got, ErrUnauthenticated) {
		t.Fatalf("revoked read committed: %v", got)
	}
	select {
	case <-logout:
	case <-time.After(5 * time.Second):
		t.Fatal("logout did not drain")
	}
	if len(s.audits) != 0 || w.Lifetime().Err() != nil {
		t.Fatal("revoked proposal changed target")
	}
}
func TestCredentialProposalRechecksRevisionAfterRead(t *testing.T) {
	entered, proceed := make(chan struct{}), make(chan struct{})
	var expectedActor string
	m, s, a, w := proposalFixture(t, func(_ context.Context, actor string, revision uint64) (string, error) {
		if actor != expectedActor || revision != 1 {
			t.Error("proposal lookup lost exact binding")
		}
		close(entered)
		<-proceed
		return fixtureHash(), nil
	})
	expectedActor = w.ActorID()
	done := make(chan error, 1)
	go func() { done <- m.ChangeAccountWithCredentialProposal(context.Background(), a, changeFor(w)) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("read did not begin")
	}
	change := changeFor(w)
	change.Capabilities = []Capability{Read}
	if err := m.ChangeAccount(context.Background(), a, change); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if got := awaitAccount(t, done); !errors.Is(got, ErrAccountConflict) {
		t.Fatalf("stale proposal committed: %v", got)
	}
	if len(s.audits) != 1 || s.snapshot.Accounts[1].Revision != 2 {
		t.Fatal("stale proposal changed durable revision")
	}
}

func TestCredentialProposalCommitsAuditedReset(t *testing.T) {
	m, s, a, w := proposalFixture(t, func(context.Context, string, uint64) (string, error) { return fixtureHash(), nil })
	if err := m.ChangeAccountWithCredentialProposal(context.Background(), a, changeFor(w)); err != nil {
		t.Fatal(err)
	}
	if len(s.audits) != 1 || s.audits[0].Operation != "credential_reset" || s.snapshot.Accounts[1].Revision != 2 || w.Lifetime().Err() == nil {
		t.Fatal("credential reset missing durable audit/revocation")
	}
	if _, err := m.Lookup(a.Token); err != nil {
		t.Fatal("unrelated requester lost session", err)
	}
}
func TestCredentialProposalRedactsUnknownStoreErrors(t *testing.T) {
	m, s, a, w := proposalFixture(t, func(context.Context, string, uint64) (string, error) {
		return "", errors.New("private-verifier-and-path")
	})
	if err := m.ChangeAccountWithCredentialProposal(context.Background(), a, changeFor(w)); err != ErrConfiguration {
		t.Fatalf("private store error escaped: %v", err)
	}
	if len(s.audits) != 0 {
		t.Fatal("failed proposal committed")
	}
}
