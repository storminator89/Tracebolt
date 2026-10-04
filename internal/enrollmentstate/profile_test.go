package enrollmentstate

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"testing"
)

func TestCollectionProfileLedgerAndProofIsolation(t *testing.T) {
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational} {
		b := binding()
		b.CollectionProfile = profile
		cfg := DefaultConfig(b)
		e, err := New(cfg)
		if err != nil {
			t.Fatal("selected profile rejected")
		}
		f := newClaimFixture(t, 1)
		f.challenge.CollectionProfile = profile
		initial := f.create(t, e)
		other := f
		other.challenge.CollectionProfile = enrollmentcrypto.CollectionProfile
		if profile == enrollmentcrypto.CollectionProfile {
			other.challenge.CollectionProfile = enrollmentcrypto.CollectionProfileOperational
		}
		if _, err := e.Claim(context.Background(), f.command(initial, testNow+1), other.proof(t, testNow+1)); err == nil {
			t.Fatal("cross-profile claim accepted")
		}
		if _, err := e.Claim(context.Background(), f.command(initial, testNow+1), f.proof(t, testNow+1)); err != nil {
			t.Fatal("selected claim rejected")
		}
		raw, err := e.EncodeTrustedLedger()
		if err != nil {
			t.Fatal("ledger encode")
		}
		defer clear(raw)
		if _, err := RestoreTrustedLedger(cfg, raw); err != nil {
			t.Fatal("selected reopen rejected")
		}
		cfg.Binding.CollectionProfile = other.challenge.CollectionProfile
		if _, err := RestoreTrustedLedger(cfg, raw); err == nil {
			t.Fatal("existing profile changed in place")
		}
	}
}
