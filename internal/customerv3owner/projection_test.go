package customerv3owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
)

func projectionProof(t *testing.T, a *activationFixture, key ed25519.PrivateKey, statusPurpose bool) (string, []byte) {
	t.Helper()
	p := a.intent.Approval.Candidate.Pending
	var c customerclaim.Context
	var err error
	if statusPurpose {
		c, err = a.pool.IssueStatus("192.0.2.1", p.CustomerID, p.InstallerProfileID, p.ClaimID)
	} else {
		c, err = a.pool.IssueCredentialV3("192.0.2.1", p.CustomerID, p.InstallerProfileID, p.ClaimID)
	}
	if err != nil {
		t.Fatal(err)
	}
	m := customerclaim.Metadata{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, Origin: p.Origin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: p.IssuerFingerprint, ClaimID: p.ClaimID, RequestID: p.RequestID, KeyFingerprint: p.KeyFingerprint, CSRHash: p.CSRHash, ClaimHash: p.ClaimHash, ComparisonCode: p.ComparisonCode}
	id := id("request", 129)
	msg, err := customerclaim.StatusSigningMessage(c, m, p.PublicKeyDER, id, a.f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.EncodeStatus(c, m, p.PublicKeyDER, id, ed25519.Sign(a.f.deviceKey, msg), a.f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, a.f.deviceKey) {
		var body map[string]string
		if err = json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		body["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, msg))
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	return c.Challenge, raw
}

func projection(a *activationFixture, nonce string, raw []byte, emit func(customerissuance.PublicIntent, func() error) error) error {
	f := a.f
	return f.store.WithPublicProjection(context.Background(), f.pending, a.pool, a.budget, nonce, raw, f.issuer, f.root, f.clock, f.original, f.issuance, f.storage, emit)
}

func TestPublicProjectionProofAndMinimalOutput(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	a.f.sessionEnded = true
	a.f.revision++
	nonce, raw := projectionProof(t, a, a.f.deviceKey, true)
	called := 0
	err := projection(a, nonce, raw, func(p customerissuance.PublicIntent, guard func() error) error {
		called++
		if err := guard(); err != nil {
			return err
		}
		want, err := customerissuance.ProjectPublic(a.intent)
		if err != nil || p != want {
			t.Fatal("projection mismatch", err)
		}
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"actor", "customerRevision", "operationId", "csr", "publicKeyDer", "comparisonCode", "managerDigest"} {
			if bytes.Contains(bytes.ToLower(data), bytes.ToLower([]byte(forbidden))) {
				t.Fatal("private field exposed", forbidden)
			}
		}
		return nil
	})
	if err != nil || called != 1 {
		t.Fatal("projection failed", err, called)
	}
	if err = projection(a, nonce, raw, func(customerissuance.PublicIntent, func() error) error { t.Fatal("replayed projection"); return nil }); err == nil {
		t.Fatal("replayed challenge accepted")
	}
}

func TestPublicProjectionRejectsInvalidAuthorityAndProof(t *testing.T) {
	for _, test := range []string{"wrong key", "wrong purpose", "expired challenge", "expired deadline", "customer revoked", "issuer revoked", "issuance revoked"} {
		t.Run(test, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			key := a.f.deviceKey
			if test == "wrong key" {
				_, key, _ = ed25519.GenerateKey(rand.Reader)
			}
			nonce, raw := projectionProof(t, a, key, test != "wrong purpose")
			switch test {
			case "expired challenge":
				a.f.now = a.f.now.Add(time.Minute)
			case "expired deadline":
				a.f.now = time.Unix(a.intent.Approval.Candidate.Pending.DeadlineAt, 0)
			case "customer revoked":
				a.f.allowed = false
			case "issuer revoked":
				a.f.issuerRevoked = true
			case "issuance revoked":
				a.f.issuanceRevoked = true
			}
			called := false
			if err := projection(a, nonce, raw, func(customerissuance.PublicIntent, func() error) error { called = true; return nil }); err == nil || called {
				t.Fatal("failed proof/authority reached callback", err)
			}
		})
	}
}

func TestPublicProjectionBusyAndCallbackCleanup(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	nonce, raw := projectionProof(t, a, a.f.deviceKey, true)
	one, _ := a.budget.Acquire(context.Background())
	two, _ := a.budget.Acquire(context.Background())
	if err := projection(a, nonce, raw, func(customerissuance.PublicIntent, func() error) error { t.Fatal("busy callback"); return nil }); !errors.Is(err, customerbudget.ErrBusy) {
		t.Fatal(err)
	}
	one.Release()
	two.Release()
	marker := errors.New("callback failed")
	if err := projection(a, nonce, raw, func(customerissuance.PublicIntent, func() error) error { return marker }); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	if a.budget.InUse() != 0 {
		t.Fatal("slot leaked")
	}
	nonce, raw = projectionProof(t, a, a.f.deviceKey, true)
	if err := projection(a, nonce, raw, func(customerissuance.PublicIntent, func() error) error { panic("callback") }); !errors.Is(err, ErrUncertain) {
		t.Fatal(err)
	}
	if a.budget.InUse() != 0 {
		t.Fatal("panic leaked slot")
	}
	nonce, raw = projectionProof(t, a, a.f.deviceKey, true)
	if err := projection(a, nonce, raw, func(_ customerissuance.PublicIntent, guard func() error) error { return guard() }); err != nil {
		t.Fatal("locks not released", err)
	}
}

func TestPublicProjectionLossAfterHandoffIsUncertain(t *testing.T) {
	for _, name := range []string{"authority", "clock"} {
		t.Run(name, func(t *testing.T) {
			a := newActivationFixture(t, "sqlite")
			nonce, raw := projectionProof(t, a, a.f.deviceKey, true)
			err := projection(a, nonce, raw, func(_ customerissuance.PublicIntent, guard func() error) error {
				if err := guard(); err != nil {
					t.Fatal(err)
				}
				if name == "authority" {
					a.f.issuanceRevoked = true
				} else {
					a.f.now = a.f.now.Add(time.Minute)
				}
				return nil
			})
			if !errors.Is(err, ErrUncertain) {
				t.Fatal("handoff uncertainty lost", err)
			}
		})
	}
}

func TestPublicProjectionRequiresCallbackGuard(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	nonce, raw := projectionProof(t, a, a.f.deviceKey, true)
	if err := projection(a, nonce, raw, func(customerissuance.PublicIntent, func() error) error { return nil }); !errors.Is(err, ErrUncertain) {
		t.Fatal("handoff without response guard reported success", err)
	}
}

func TestPublicProjectionGuardFailureIsStickyAndExpires(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	nonce, raw := projectionProof(t, a, a.f.deviceKey, true)
	var retained func() error
	err := projection(a, nonce, raw, func(_ customerissuance.PublicIntent, guard func() error) error {
		retained = guard
		a.f.issuanceRevoked = true
		if guard() == nil {
			t.Fatal("revoked guard accepted")
		}
		a.f.issuanceRevoked = false
		if err := guard(); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if !errors.Is(err, ErrUncertain) {
		t.Fatal("failed guard was forgotten", err)
	}
	if retained == nil || retained() == nil {
		t.Fatal("guard survived callback")
	}
}

func TestPublicProjectionGuardPanicCannotBeSwallowed(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	nonce, raw := projectionProof(t, a, a.f.deviceKey, true)
	trigger := false
	storage := func(ctx context.Context) error {
		if trigger {
			trigger = false
			panic("temporary guard failure")
		}
		return a.f.storage(ctx)
	}
	f := a.f
	err := f.store.WithPublicProjection(context.Background(), f.pending, a.pool, a.budget, nonce, raw, f.issuer, f.root, f.clock, f.original, f.issuance, storage, func(_ customerissuance.PublicIntent, guard func() error) error {
		trigger = true
		func() { defer func() { _ = recover() }(); _ = guard() }()
		return nil
	})
	if !errors.Is(err, ErrUncertain) {
		t.Fatal("guard panic was swallowed", err)
	}
}

func TestPublicProjectionRequiresCommittedIntent(t *testing.T) {
	a := newActivationFixture(t, "sqlite")
	p := a.intent.Approval.Candidate.Pending
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pendingOnly := a.f.claim(t, key, 130)
	c, err := a.pool.IssueStatus("192.0.2.1", p.CustomerID, p.InstallerProfileID, pendingOnly.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err = projection(a, c.Challenge, []byte("{}"), func(customerissuance.PublicIntent, func() error) error { called = true; return nil }); !errors.Is(err, ErrConflict) || called {
		t.Fatal("unapproved claim exposed", err)
	}
}
