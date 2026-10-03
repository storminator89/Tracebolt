package enrollmentstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
)

func TestAuthorizeCertificateRequiresExactActivatedCurrentDurableIdentity(t *testing.T) {
	f, s, path := fixtureStore(t)
	ctx := context.Background()
	snapshot, intent := f.toIntent(t, s)
	cert := f.issue(t, intent)
	at := time.Unix(testNow+10, 0)
	if _, err := s.AuthorizeCertificate(ctx, cert.DER(), at); !errors.Is(err, enrollmentstate.ErrNotFound) {
		t.Fatal("uncommitted certificate authorized", err)
	}
	snapshot, err := s.CommitIssued(ctx, control(snapshot, 5), cert)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthorizeCertificate(ctx, cert.DER(), at); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("issued but unactivated certificate authorized", err)
	}
	c := control(snapshot, 6)
	snapshot, err = s.Activate(ctx, c, f.activation(t, cert, c))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.AuthorizeCertificate(ctx, cert.DER(), at)
	if err != nil || got != snapshot {
		t.Fatal("activated authority mismatch", err)
	}
	der := cert.DER()
	der[len(der)-1] ^= 1
	if _, err = s.AuthorizeCertificate(ctx, der, at); !errors.Is(err, enrollmentstate.ErrNotFound) {
		t.Fatal("non-exact DER accepted", err)
	}
	if _, err = s.AuthorizeCertificate(ctx, cert.DER(), time.Unix(snapshot.Intent.NotAfter, 0)); !errors.Is(err, enrollmentstate.ErrExpired) {
		t.Fatal("expired credential accepted", err)
	}
	if _, err = s.AuthorizeCertificate(ctx, cert.DER(), time.Unix(snapshot.UpdatedAt-1, 0)); !errors.Is(err, enrollmentstate.ErrInvalid) {
		t.Fatal("backward time accepted", err)
	}
	other := f.open(t, path)
	revoke := control(snapshot, 20)
	revoke.Now = at.Unix()
	if _, err = other.Terminate(ctx, enrollmentstate.TerminalCommand{Control: revoke, State: enrollmentstate.Revoked}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthorizeCertificate(ctx, cert.DER(), at.Add(time.Second)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("cached authorization survived independent revocation", err)
	}
}

func TestAuthorizeCertificateUnavailableNeverMeansUnauthorized(t *testing.T) {
	_, s, _, _, cert := activeFixture(t)
	s.Close()
	if _, err := s.AuthorizeCertificate(context.Background(), cert.DER(), time.Unix(testNow+10, 0)); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
	for _, store := range []*Store{nil, {}} {
		if _, err := store.AuthorizeCertificate(context.Background(), cert.DER(), time.Unix(testNow+10, 0)); !errors.Is(err, ErrStorage) {
			t.Fatal("zero store did not fail closed", err)
		}
	}
}
