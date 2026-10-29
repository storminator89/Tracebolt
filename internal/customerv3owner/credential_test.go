package customerv3owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerv3proof"
)

func (a *activationFixture) credentialRequest(t *testing.T, n int, credential bool) CredentialRequest {
	t.Helper()
	p := a.intent.Approval.Candidate.Pending
	c, e := a.pool.IssueCredentialV3("192.0.2.1", p.CustomerID, p.InstallerProfileID, p.ClaimID)
	if !credential {
		c, e = a.pool.IssueActivationV3("192.0.2.1", p.CustomerID, p.InstallerProfileID, p.ClaimID)
	}
	if e != nil {
		t.Fatal(e)
	}
	req := id("request", n)
	msg, e := customerv3proof.SigningMessage(a.intent, customerv3proof.Credential, c, req, "", a.f.now)
	if e != nil {
		t.Fatal(e)
	}
	return CredentialRequest{ClaimID: p.ClaimID, IntentID: a.intent.IntentID, IntentDigest: a.cert.IntentDigest, RequestID: req, Nonce: c.Challenge, Signature: ed25519.Sign(a.f.deviceKey, msg)}
}
func (a *activationFixture) credential(ctx context.Context, r CredentialRequest, emit func(customerissuance.PublicIntent, []byte) error) error {
	f := a.f
	return f.store.WithCredential(ctx, f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(p customerissuance.PublicIntent, b []byte, guard func() error) error {
		if e := guard(); e != nil {
			return e
		}
		return emit(p, b)
	})
}

func TestCredentialExactFreshRetryAndProjection(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	a.f.revision++
	a.f.sessionEnded = true
	var first customerissuance.PublicIntent
	var der []byte
	r := a.credentialRequest(t, 201, true)
	if err := a.credential(context.Background(), r, func(p customerissuance.PublicIntent, b []byte) error {
		first = p
		der = bytes.Clone(b)
		b[0] ^= 1
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, a.cert.DER) || first.IntentDigest != a.cert.IntentDigest {
		t.Fatal("incorrect retained bytes")
	}
	raw, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"actor", "customerRevision", "operationId", "csr", "publicKeyDer", "requestId"} {
		if bytes.Contains(bytes.ToLower(raw), bytes.ToLower([]byte(s))) {
			t.Fatal("internal field disclosed", s)
		}
	}
	if err = a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error { t.Fatal("replayed challenge emitted"); return nil }); err == nil {
		t.Fatal("replayed challenge accepted")
	}
	second := a.credentialRequest(t, 202, true)
	if err = a.credential(context.Background(), second, func(p customerissuance.PublicIntent, b []byte) error {
		if p != first || !bytes.Equal(b, der) {
			t.Fatal("fresh retry changed bytes")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := a.f.store.ActivationRecords(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatal("read changed activation", err)
	}
}

func TestCredentialRejectsBadProofAndBinding(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*activationFixture, *CredentialRequest)
	}{
		{"wrong key", func(_ *activationFixture, r *CredentialRequest) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			r.Signature = ed25519.Sign(key, []byte("different key"))
		}},
		{"wrong claim", func(_ *activationFixture, r *CredentialRequest) { r.ClaimID = id("claim", 999) }},
		{"wrong intent", func(_ *activationFixture, r *CredentialRequest) { r.IntentID = id("intent", 999) }},
		{"wrong digest", func(_ *activationFixture, r *CredentialRequest) { r.IntentDigest = strings.Repeat("a", 64) }},
		{"issuer revoked", func(a *activationFixture, _ *CredentialRequest) { a.f.issuerRevoked = true }},
		{"approval revoked", func(a *activationFixture, _ *CredentialRequest) { a.f.issuanceRevoked = true }},
		{"original revoked", func(a *activationFixture, _ *CredentialRequest) { a.f.allowed = false }},
		{"expired", func(a *activationFixture, _ *CredentialRequest) { a.f.now = a.f.now.Add(time.Hour) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			r := a.credentialRequest(t, 203, true)
			tc.mutate(a, &r)
			called := false
			err := a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("invalid proof disclosed certificate")
			}
		})
	}
	a := newActivationFixture(t, "sqlite")
	r := a.credentialRequest(t, 204, false)
	if err := a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error { t.Fatal("wrong-purpose disclosed"); return nil }); err == nil {
		t.Fatal("activation nonce accepted")
	}
}

func TestCredentialPostHandoffUncertaintyAndLocks(t *testing.T) {
	for _, tc := range []struct {
		name string
		emit func(*activationFixture) error
	}{
		{"error", func(*activationFixture) error { return errors.New("emit failed") }},
		{"panic", func(*activationFixture) error { panic("fixture emit panic") }},
		{"revoked after callback", func(a *activationFixture) error { a.f.issuerRevoked = true; return nil }},
		{"expired after callback", func(a *activationFixture) error { a.f.now = a.f.now.Add(time.Hour); return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			r := a.credentialRequest(t, 205, true)
			err := a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error {
				if a.budget.InUse() != 1 {
					t.Fatal("budget not held")
				}
				return tc.emit(a)
			})
			if !errors.Is(err, ErrUncertain) {
				t.Fatal("handoff outcome falsely confirmed", err)
			}
			if a.budget.InUse() != 0 {
				t.Fatal("budget leaked")
			}
		})
	}
}

func TestCredentialSharedBudgetBusyAndFreshChallenge(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.credentialRequest(t, 206, true)
	one, e := a.budget.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	two, e := a.budget.Acquire(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error { t.Fatal("busy disclosed"); return nil }); !errors.Is(e, customerbudget.ErrBusy) {
		t.Fatal("expected busy", e)
	}
	one.Release()
	two.Release()
	if e = a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error { return nil }); e != nil {
		t.Fatal("busy consumed nonce", e)
	}
}

func TestCredentialDifferentKeyAndStoredLeafTampering(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.credentialRequest(t, 207, true)
	p := a.intent.Approval.Candidate.Pending
	c := customerclaim.Context{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, Origin: p.Origin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: p.IssuerFingerprint, Challenge: r.Nonce, ExpiresAt: a.f.now.Unix() + int64(customerclaim.MaxChallengeLifetime/time.Second)}
	msg, e := customerv3proof.SigningMessage(a.intent, customerv3proof.Credential, c, r.RequestID, "", a.f.now)
	if e != nil {
		t.Fatal(e)
	}
	_, other, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	r.Signature = ed25519.Sign(other, msg)
	if e = a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error { t.Fatal("foreign key disclosed"); return nil }); e == nil {
		t.Fatal("foreign key accepted")
	}
	r = a.credentialRequest(t, 208, true)
	var raw []byte
	if e = a.f.db.QueryRow(`SELECT body FROM customer_v3_certificates WHERE claim_id=?`, r.ClaimID).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var record CertificateRecord
	if e = json.Unmarshal(raw, &record); e != nil {
		t.Fatal(e)
	}
	record.DER[0] ^= 1
	raw, e = json.Marshal(record)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.f.db.Exec(`UPDATE customer_v3_certificates SET body=? WHERE claim_id=?`, raw, r.ClaimID); e != nil {
		t.Fatal(e)
	}
	if e = a.credential(context.Background(), r, func(customerissuance.PublicIntent, []byte) error { t.Fatal("altered leaf disclosed"); return nil }); !errors.Is(e, ErrStorage) {
		t.Fatal("altered leaf accepted", e)
	}
}

func TestCredentialSerializesDuringSynchronousHandoff(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	first, second := a.credentialRequest(t, 209, true), a.credentialRequest(t, 210, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 2)
	go func() {
		done <- a.credential(ctx, first, func(customerissuance.PublicIntent, []byte) error {
			close(entered)
			select {
			case <-release:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("first callback did not start")
	}
	secondEntered := make(chan struct{})
	go func() {
		done <- a.credential(ctx, second, func(customerissuance.PublicIntent, []byte) error { close(secondEntered); return nil })
	}()
	select {
	case <-secondEntered:
		close(release)
		t.Fatal("second handoff bypassed held owner")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	for n := 0; n < 2; n++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-secondEntered:
	default:
		t.Fatal("second handoff did not resume")
	}
}

func TestCredentialResponseGuardIsMandatoryAndBounded(t *testing.T) {
	for _, name := range []string{"missing", "failure ignored", "timeout", "panic"} {
		t.Run(name, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			r := a.credentialRequest(t, 211, true)
			f := a.f
			ctx := context.Background()
			cancel := func() {}
			if name == "timeout" {
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
			}
			defer cancel()
			var saved func() error
			err := f.store.WithCredential(ctx, f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(_ customerissuance.PublicIntent, _ []byte, guard func() error) error {
				saved = guard
				switch name {
				case "missing":
					return nil
				case "failure ignored":
					if err := guard(); err != nil {
						return err
					}
					f.issuerRevoked = true
					if guard() == nil {
						t.Fatal("revoked guard succeeded")
					}
					return nil
				case "timeout":
					<-ctx.Done()
					if guard() == nil {
						t.Fatal("expired context guard succeeded")
					}
					return nil
				default:
					panic("fixture response panic")
				}
			})
			if !errors.Is(err, ErrUncertain) {
				t.Fatal("unconfirmed response treated as success", err)
			}
			if saved == nil || saved() == nil {
				t.Fatal("guard remained valid after callback")
			}
			if a.budget.InUse() != 0 {
				t.Fatal("budget not released")
			}
		})
	}
}

func TestCredentialResponseGuardSuccess(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.credentialRequest(t, 212, true)
	f := a.f
	var saved func() error
	err := f.store.WithCredential(context.Background(), f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, func(_ customerissuance.PublicIntent, _ []byte, guard func() error) error {
		saved = guard
		return guard()
	})
	if err != nil {
		t.Fatal(err)
	}
	if saved == nil || saved() == nil {
		t.Fatal("guard remained valid after completion")
	}
}

func TestCredentialRejectsClockRegressionAfterEdge(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.credentialRequest(t, 213, true)
	f := a.f
	current := f.now
	edgeMode := false
	calls := 0
	clock := func() time.Time {
		if edgeMode {
			calls++
			if calls == 4 {
				return current.Add(2 * time.Second)
			}
		}
		return current
	}
	err := f.store.WithCredential(context.Background(), f.pending, a.pool, a.budget, r, f.issuer, f.root, clock, f.original, f.issuance, f.storage, func(_ customerissuance.PublicIntent, _ []byte, guard func() error) error {
		edgeMode = true
		if err := guard(); err != nil {
			t.Fatal("initial edge rejected", err)
		}
		edgeMode = false
		current = current.Add(time.Second)
		if guard() == nil {
			t.Fatal("clock regression behind earlier edge accepted")
		}
		return nil
	})
	if !errors.Is(err, ErrUncertain) {
		t.Fatal("clock regression was confirmed", err)
	}
}

func TestCredentialResponseGuardPanicIsSticky(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	r := a.credentialRequest(t, 214, true)
	f := a.f
	calls := 0
	guardStorage := func(context.Context) error {
		calls++
		if calls == 3 {
			panic("fixture response guard panic")
		}
		return nil
	}
	err := f.store.WithCredential(context.Background(), f.pending, a.pool, a.budget, r, f.issuer, f.root, f.clock, f.original, f.issuance, guardStorage, func(_ customerissuance.PublicIntent, _ []byte, guard func() error) error {
		if guard() == nil {
			t.Fatal("panicking guard succeeded")
		}
		if guard() != nil {
			t.Fatal("fixture subsequent guard should pass")
		}
		return nil
	})
	if !errors.Is(err, ErrUncertain) {
		t.Fatal("guard panic was not sticky", err)
	}
}
