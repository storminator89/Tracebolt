package customerproofdomain

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customeradmission"
	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	_ "modernc.org/sqlite"
)

type fixtureLease struct{}

func (fixtureLease) Check() error { return nil }
func (fixtureLease) Release()     {}
func fixtureAuthority(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
	return fixtureLease{}, nil
}

func TestOneDomainSharesBudgetAcrossActualProofs(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	clock := func() time.Time { return now }
	pool, err := customerchallenge.New(customerchallenge.Binding{ManagerID: "manager_" + strings.Repeat("1", 32), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: strings.Repeat("a", 64)}, clock)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer db.Close()
	if err = customerpending.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := customerpending.New(db)
	if err != nil {
		t.Fatal(err)
	}
	budget := customerbudget.New()
	domain, err := NewWithBudget(pool, store, clock, fixtureAuthority, budget)
	if err != nil {
		t.Fatal(err)
	}
	if domain.budget != budget {
		t.Fatal("domain replaced manager-owned budget")
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	customer := "customer_" + strings.Repeat("2", 32)
	profile := "profile_" + strings.Repeat("3", 32)
	makeClaim := func(id, request string) (customerclaim.Context, []byte) {
		c, e := pool.Issue("192.0.2.1", customer, profile, id)
		if e != nil {
			t.Fatal(e)
		}
		message, e := customerclaim.SigningMessage(c, request, csr, clock())
		if e != nil {
			t.Fatal(e)
		}
		raw, e := customerclaim.Encode(c, request, csr, ed25519.Sign(key, message), clock())
		if e != nil {
			t.Fatal(e)
		}
		return c, raw
	}
	claim, raw := makeClaim("claim_"+strings.Repeat("4", 32), "request_"+strings.Repeat("5", 32))
	record, err := domain.Admit(ctx, claim.Challenge, raw)
	if err != nil {
		t.Fatal(err)
	}
	status, err := pool.IssueStatus("192.0.2.1", customer, profile, record.ClaimID)
	if err != nil {
		t.Fatal(err)
	}
	m := customerclaim.Metadata{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, Origin: record.Origin, AgentOrigin: record.AgentOrigin, IssuerFingerprint: record.IssuerFingerprint, ClaimID: record.ClaimID, RequestID: record.RequestID, KeyFingerprint: record.KeyFingerprint, CSRHash: record.CSRHash, ClaimHash: record.ClaimHash, ComparisonCode: record.ComparisonCode}
	request := "request_" + strings.Repeat("6", 32)
	message, err := customerclaim.StatusSigningMessage(status, m, record.PublicKeyDER, request, clock())
	if err != nil {
		t.Fatal(err)
	}
	statusRaw, err := customerclaim.EncodeStatus(status, m, record.PublicKeyDER, request, ed25519.Sign(key, message), clock())
	if err != nil {
		t.Fatal(err)
	}
	next, nextRaw := makeClaim("claim_"+strings.Repeat("7", 32), "request_"+strings.Repeat("8", 32))
	reserved, err := budget.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- domain.WithPendingStatus(ctx, status.Challenge, statusRaw, func(v customerpending.PendingStatus) error {
			if v.State != "pending" {
				return errors.New("wrong state")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("status did not reach callback")
	}
	if _, err = domain.Admit(ctx, next.Challenge, nextRaw); !errors.Is(err, customeradmission.ErrBusy) {
		t.Fatalf("claim did not share bound: %v", err)
	}
	reserved.Release()
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if _, err = domain.Admit(ctx, next.Challenge, nextRaw); err != nil {
		t.Fatalf("busy claim consumed challenge: %v", err)
	}
	if domain.budget.InUse() != 0 {
		t.Fatal("shared proof slot leaked")
	}
}

func TestUninitializedDomainFailsClosed(t *testing.T) {
	var d *Domain
	if _, err := d.Admit(context.Background(), "x", []byte("x")); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil domain accepted")
	}
	if err := (&Domain{}).WithPendingStatus(context.Background(), "x", []byte("x"), func(customerpending.PendingStatus) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("zero domain accepted")
	}
	if _, err := New(nil, nil, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil dependencies accepted")
	}
	if _, err := NewWithBudget(nil, nil, nil, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil shared budget accepted")
	}
	if _, err := NewWithBudget(nil, nil, nil, nil, &customerbudget.Budget{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("uninitialized shared budget accepted")
	}
}
