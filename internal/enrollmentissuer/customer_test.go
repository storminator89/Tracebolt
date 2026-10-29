package enrollmentissuer_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerapprovalstore"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerissuance"
	"localrmm/internal/customerpending"
	"localrmm/internal/enrollmentissuer"
)

func customerIntent(t *testing.T, f fixture) customerissuance.Intent {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "untrusted-csr-subject"}, DNSNames: []string{"untrusted-csr.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	id := func(prefix, digit string) string { return prefix + "_" + strings.Repeat(digit, 32) }
	c := customerclaim.Context{ManagerID: id("manager", "1"), CustomerID: id("customer", "2"), InstallerProfileID: id("profile", "3"), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: f.intent.IssuerFingerprint, ClaimID: id("claim", "4"), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{4}, 32)), ExpiresAt: now.Unix() + 60}
	request := id("request", "5")
	msg, err := customerclaim.SigningMessage(c, request, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(c, request, csr, ed25519.Sign(key, msg), now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := customerclaim.Verify(raw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	m := proof.Metadata()
	p := customerpending.Record{Version: "tracebolt.customer-pending.v1", ManagerID: m.ManagerID, CustomerID: m.CustomerID, InstallerProfileID: m.InstallerProfileID, Origin: m.Origin, AgentOrigin: m.AgentOrigin, IssuerFingerprint: m.IssuerFingerprint, ClaimID: m.ClaimID, RequestID: m.RequestID, KeyFingerprint: m.KeyFingerprint, CSRHash: m.CSRHash, ClaimHash: m.ClaimHash, ComparisonCode: m.ComparisonCode, PublicKeyDER: proof.PublicKeyDER(), CreatedAt: now.Unix() - 10, DeadlineAt: now.Unix() - 10 + int64(customerpending.PendingLifetime/time.Second)}
	expected := customerpending.ReviewExpectation{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, ClaimHash: p.ClaimHash, KeyFingerprint: p.KeyFingerprint, ManagerDigest: strings.Repeat("b", 64), CustomerRevision: 1, DeadlineAt: p.DeadlineAt}
	decision := customerapproval.Decision{OperationID: id("request", "6"), DeviceID: id("agent", "7"), Acknowledged: true, FingerprintCompared: true}
	candidate, err := customerapproval.Build(expected, p, decision, now)
	if err != nil {
		t.Fatal(err)
	}
	record := customerapprovalstore.Record{Version: "tracebolt.customer-approval-record.v1", Actor: customerapprovalstore.Actor{Mode: "shared"}, Candidate: candidate}
	intent, err := customerissuance.Build(record, id("intent", "8"), strings.Repeat("9", 32), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestCustomerSignerFixedTemplateAndDeterminism(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	intent := customerIntent(t, f)
	handle := f.issuer(t)
	rebuilt := f.issuer(t)
	first, err := handle.SignCustomer(context.Background(), intent, now)
	if err != nil || !first.Valid() {
		t.Fatal("v3 sign failed", err)
	}
	if expected, _ := customerissuance.Digest(intent); first.IntentDigest() != expected {
		t.Fatal("intent digest changed")
	}
	leaf, err := x509.ParseCertificate(first.DER())
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != intent.Approval.Candidate.DeviceID || len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses)+len(leaf.URIs) != 0 || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.Extensions) != 4 {
		t.Fatal("unexpected client template")
	}
	if bytes.Contains(first.DER(), []byte("untrusted-csr")) {
		t.Fatal("CSR field copied")
	}
	baseline := first.DER()
	clear(f.key) // handles must own their private copies.
	for _, signer := range []*enrollmentissuer.Issuer{handle, rebuilt} {
		second, err := signer.SignCustomer(context.Background(), intent, now)
		if err != nil || !bytes.Equal(second.DER(), baseline) {
			t.Fatal("non-deterministic or missing issuer key copy", err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := handle.SignCustomer(context.Background(), intent, now)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(v.DER(), baseline) {
				errs <- errors.New("concurrent output changed")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestCustomerSignerRejectsInvalidContextAndIntent(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	intent := customerIntent(t, f)
	handle := f.issuer(t)
	if _, err := handle.SignCustomer(nil, intent, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := handle.SignCustomer(ctx, intent, now); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel ignored")
	}
	var nilIssuer *enrollmentissuer.Issuer
	if _, err := nilIssuer.SignCustomer(context.Background(), intent, now); !errors.Is(err, enrollmentissuer.ErrConfiguration) {
		t.Fatal("nil issuer accepted")
	}
	for name, edit := range map[string]func(*customerissuance.Intent){"scope": func(i *customerissuance.Intent) { i.CollectionProfile = "basic-readonly-v1" }, "subject binding": func(i *customerissuance.Intent) {
		i.Approval.Candidate.Pending.ClaimID = "claim_" + strings.Repeat("b", 32)
	}, "issuer": func(i *customerissuance.Intent) {
		i.Approval.Candidate.Pending.IssuerFingerprint = strings.Repeat("b", 64)
	}, "serial": func(i *customerissuance.Intent) { i.SerialHex = strings.Repeat("0", 32) }, "window": func(i *customerissuance.Intent) { i.NotAfter = i.NotBefore }, "v2 domain": func(i *customerissuance.Intent) { i.Version = "tracebolt.enrollment-intent.v2" }} {
		t.Run(name, func(t *testing.T) {
			v := intent
			edit(&v)
			if _, err := handle.SignCustomer(context.Background(), v, now); !errors.Is(err, enrollmentissuer.ErrIntent) {
				t.Fatal("invalid customer intent accepted", err)
			}
		})
	}
	for name, at := range map[string]time.Time{"before": now.Add(-time.Second), "expired": time.Unix(intent.NotAfter, 0), "missing": time.Time{}} {
		t.Run(name, func(t *testing.T) {
			if _, err := handle.SignCustomer(context.Background(), intent, at); !errors.Is(err, enrollmentissuer.ErrIntent) {
				t.Fatal("invalid signing time accepted", err)
			}
		})
	}
	other := makeFixture(t, nil, nil, nil)
	otherIntent := customerIntent(t, other)
	if _, err := handle.SignCustomer(context.Background(), otherIntent, now); !errors.Is(err, enrollmentissuer.ErrIntent) {
		t.Fatal("different issuer accepted", err)
	}
}

func TestCustomerSignerAloneDoesNotEstablishApproval(t *testing.T) {
	f := makeFixture(t, nil, nil, nil)
	intent := customerIntent(t, f)
	// A structurally valid public candidate cannot demonstrate that a human or
	// authoritative enrollment transaction approved it. The signer is a narrowly
	// scoped cryptographic primitive and intentionally cannot make that decision.
	intent.Approval.Candidate.CustomerRevision++
	if _, err := f.issuer(t).SignCustomer(context.Background(), intent, now); err != nil {
		t.Fatal("fixture shows only caller-owned authority, not signer rejection", err)
	}
}
