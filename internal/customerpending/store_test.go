package customerpending

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
	_ "modernc.org/sqlite"
)

type testLease struct{ guard func() error }

func (l testLease) Check() error { return l.guard() }
func (testLease) Release()       {}

type trackingLease struct {
	check   func() error
	release func()
}

func (l trackingLease) Check() error { return l.check() }
func (l trackingLease) Release()     { l.release() }
func leaseFor(guard func() error) AcquireAuthority {
	return func(context.Context, customerclaim.Metadata) (AuthorityLease, error) { return testLease{guard}, nil }
}

func openFixture(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

func proofFixture(t *testing.T, now time.Time, n int, customer, profile string, key ed25519.PrivateKey, nonce byte) customerclaim.Verified {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	c := customerclaim.Context{ManagerID: "manager_" + strings.Repeat("1", 32), CustomerID: customer, InstallerProfileID: profile, Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: strings.Repeat("a", 64), ClaimID: fmt.Sprintf("claim_%032x", n), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{nonce}, 32)), ExpiresAt: now.Unix() + 60}
	id := fmt.Sprintf("request_%032x", n)
	message, err := customerclaim.SigningMessage(c, id, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(c, id, csr, ed25519.Sign(key, message), now)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := customerclaim.Verify(raw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestPendingDurableExactRetryAndOriginalBinding(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	clock := func() time.Time { return now }
	guard := func() error { return nil }
	path := filepath.Join(t.TempDir(), "pending.db")
	db := openFixture(t, path)
	if err := Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(ctx, db); !errors.Is(err, ErrStorage) {
		t.Fatal("existing schema adopted", err)
	}
	s, _ := New(db)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	customer := "customer_" + strings.Repeat("2", 32)
	profile := "profile_" + strings.Repeat("3", 32)
	p := proofFixture(t, now, 1, customer, profile, key, 4)
	r, err := s.Accept(ctx, p, clock, leaseFor(guard))
	if err != nil {
		t.Fatal(err)
	}
	// The same CSR/key/request with a fresh challenge yields the same semantic
	// claim; a retry never extends its original creation or deadline.
	now = now.Add(time.Second)
	retry := proofFixture(t, now, 1, customer, profile, key, 5)
	r2, err := s.Accept(ctx, retry, clock, leaseFor(guard))
	if err != nil || !reflect.DeepEqual(r, r2) {
		t.Fatalf("retry failed: %v", err)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for _, altered := range []customerclaim.Verified{proofFixture(t, now, 1, "customer_"+strings.Repeat("7", 32), profile, key, 6), proofFixture(t, now, 1, customer, "profile_"+strings.Repeat("7", 32), key, 7), proofFixture(t, now, 1, customer, profile, other, 8)} {
		if _, err = s.Accept(ctx, altered, clock, leaseFor(guard)); !errors.Is(err, ErrConflict) {
			t.Fatalf("identity changed: %v", err)
		}
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFixture(t, path)
	again, _ := New(reopened)
	records, err := again.Records(ctx)
	if err != nil || len(records) != 1 || !reflect.DeepEqual(records[0], r) {
		t.Fatalf("reopen failed: %v", err)
	}
	records[0].PublicKeyDER[0] ^= 1
	records, err = again.Records(ctx)
	if err != nil || !reflect.DeepEqual(records[0], r) {
		t.Fatal("mutable returned data changed durable record")
	}
	now = time.Unix(r.DeadlineAt, 0)
	expired := proofFixture(t, now, 1, customer, profile, key, 9)
	if _, err = again.Accept(ctx, expired, clock, leaseFor(guard)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired pending claim revived: %v", err)
	}
}

func TestAuthorityAndExpiryFailuresRollback(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
	if err := Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, _ := New(db)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	p := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
	denied := errors.New("authority changed")
	calls := 0
	guard := func() error {
		calls++
		if calls == 2 {
			return denied
		}
		return nil
	}
	if _, err := s.Accept(ctx, p, func() time.Time { return now }, leaseFor(guard)); !errors.Is(err, denied) {
		t.Fatalf("guard failure: %v", err)
	}
	if rows, err := s.Records(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("guard persisted write: %v", err)
	}
	calls = 0
	finalGuard := func() error {
		calls++
		if calls == 3 {
			return denied
		}
		return nil
	}
	if _, err := s.Accept(ctx, p, func() time.Time { return now }, leaseFor(finalGuard)); !errors.Is(err, denied) {
		t.Fatalf("final authority failure: %v", err)
	}
	if rows, err := s.Records(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("final authority failure persisted write: %v", err)
	}
	calls = 0
	moving := func() time.Time {
		calls++
		if calls > 1 {
			return now.Add(60 * time.Second)
		}
		return now
	}
	if _, err := s.Accept(ctx, p, moving, leaseFor(func() error { return nil })); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired proof committed: %v", err)
	}
	if rows, err := s.Records(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("expired proof persisted: %v", err)
	}
	if _, err := s.Accept(ctx, customerclaim.Verified{}, func() time.Time { return now }, leaseFor(func() error { return nil })); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero proof accepted: %v", err)
	}
	if _, err := s.Accept(ctx, p, func() time.Time { return now.Add(-time.Second) }, leaseFor(func() error { return nil })); !errors.Is(err, ErrExpired) {
		t.Fatalf("future proof under a regressed clock accepted: %v", err)
	}
}

func TestPerCustomerLimitAndMissingRowsFailClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
	if err := Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, _ := New(db)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	customer := "customer_" + strings.Repeat("2", 32)
	profile := "profile_" + strings.Repeat("3", 32)
	clock := func() time.Time { return now }
	guard := func() error { return nil }
	for i := 1; i <= MaxCustomerRecords; i++ {
		if _, err := s.Accept(ctx, proofFixture(t, now, i, customer, profile, key, byte(i)), clock, leaseFor(guard)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if _, err := s.Accept(ctx, proofFixture(t, now, MaxCustomerRecords+1, customer, profile, key, 55), clock, leaseFor(guard)); !errors.Is(err, ErrLimit) {
		t.Fatalf("customer bound not enforced: %v", err)
	}
	if _, err := s.Accept(ctx, proofFixture(t, now, MaxCustomerRecords+2, "customer_"+strings.Repeat("4", 32), profile, key, 56), clock, leaseFor(guard)); err != nil {
		t.Fatalf("other customer blocked: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM customer_pending_claims WHERE claim_id=?`, fmt.Sprintf("claim_%032x", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Records(ctx); !errors.Is(err, ErrStorage) {
		t.Fatalf("missing row silently accepted: %v", err)
	}
}

func TestConcurrentDuplicateDoesNotCreateAnotherRecord(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
	if err := Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, _ := New(db)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	customer := "customer_" + strings.Repeat("2", 32)
	profile := "profile_" + strings.Repeat("3", 32)
	p1 := proofFixture(t, now, 1, customer, profile, key, 4)
	p2 := proofFixture(t, now, 1, customer, profile, key, 5)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, p := range []customerclaim.Verified{p1, p2} {
		wg.Add(1)
		go func(p customerclaim.Verified) {
			defer wg.Done()
			_, err := s.Accept(ctx, p, func() time.Time { return now }, leaseFor(func() error { return nil }))
			errs <- err
		}(p)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.Records(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestGlobalLimitAndFreshDatabaseOnly(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
	if _, err := db.Exec(`CREATE TABLE sqliteXfoo (id INTEGER)`); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(ctx, db); !errors.Is(err, ErrStorage) {
		t.Fatalf("existing database adopted: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE sqliteXfoo`); err != nil {
		t.Fatal(err)
	}
	if err := Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, _ := New(db)
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	profile := "profile_" + strings.Repeat("3", 32)
	for i := 1; i <= MaxRecords; i++ {
		customer := fmt.Sprintf("customer_%032x", (i-1)/MaxCustomerRecords+1)
		_, err := s.Accept(ctx, proofFixture(t, now, i, customer, profile, key, byte(i)), func() time.Time { return now }, leaseFor(func() error { return nil }))
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	_, err := s.Accept(ctx, proofFixture(t, now, MaxRecords+1, "customer_"+strings.Repeat("9", 32), profile, key, 111), func() time.Time { return now }, leaseFor(func() error { return nil }))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("global bound not enforced: %v", err)
	}
}

func TestCanonicalStoredRecordTamperingFailsClosed(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	for name, mutate := range map[string]func(*Record){
		"customer":   func(r *Record) { r.CustomerID = "customer_" + strings.Repeat("7", 32) },
		"profile":    func(r *Record) { r.InstallerProfileID = "profile_" + strings.Repeat("7", 32) },
		"request":    func(r *Record) { r.RequestID = "request_" + strings.Repeat("7", 32) },
		"origin":     func(r *Record) { r.Origin = "http://manager.example.test" },
		"comparison": func(r *Record) { r.ComparisonCode = strings.Repeat("7", 32) },
		"claimHash":  func(r *Record) { r.ClaimHash = strings.Repeat("7", 64) },
		"invalidSPKI": func(r *Record) {
			r.PublicKeyDER[0] ^= 1
			h := sha256.Sum256(r.PublicKeyDER)
			r.KeyFingerprint = hex.EncodeToString(h[:])
		},
	} {
		t.Run(name, func(t *testing.T) {
			db := openFixture(t, filepath.Join(t.TempDir(), "pending.db"))
			if err := Initialize(ctx, db); err != nil {
				t.Fatal(err)
			}
			s, _ := New(db)
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			p := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
			r, err := s.Accept(ctx, p, func() time.Time { return now }, leaseFor(func() error { return nil }))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&r)
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(`UPDATE customer_pending_claims SET body=? WHERE claim_id=?`, raw, r.ClaimID); err != nil {
				t.Fatal(err)
			}
			if _, err = s.Records(ctx); !errors.Is(err, ErrStorage) {
				t.Fatalf("mutated canonical record accepted: %v", err)
			}
		})
	}
}

func TestLeaseAcquiredAfterPendingLockAndReleasedAfterCommitOrRollback(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	path := filepath.Join(t.TempDir(), "pending.db")
	db := openFixture(t, path)
	if err := Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, _ := New(db)
	other := openFixture(t, path)
	if _, err := other.Exec(`PRAGMA busy_timeout=1`); err != nil {
		t.Fatal(err)
	}
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	customer := "customer_" + strings.Repeat("2", 32)
	profile := "profile_" + strings.Repeat("3", 32)
	for n := 1; n <= 2; n++ {
		calls, released := 0, false
		acquire := func(context.Context, customerclaim.Metadata) (AuthorityLease, error) {
			if _, err := other.Exec(`UPDATE customer_pending_meta SET last_at=last_at WHERE id=1`); err == nil {
				t.Error("pending lock not held before authority acquisition")
			}
			return trackingLease{check: func() error {
				calls++
				if n == 2 && calls == 3 {
					return ErrConflict
				}
				return nil
			}, release: func() {
				released = true
				var count int
				if err := other.QueryRow(`SELECT count(*) FROM customer_pending_claims`).Scan(&count); err != nil || count != 1 {
					t.Errorf("lease released before settlement: count=%d err=%v", count, err)
				}
			}}, nil
		}
		_, err := s.Accept(ctx, proofFixture(t, now, n, customer, profile, key, byte(n)), func() time.Time { return now }, acquire)
		if n == 1 && err != nil || n == 2 && !errors.Is(err, ErrConflict) {
			t.Fatalf("unexpected acceptance: %v", err)
		}
		if !released {
			t.Fatal("authority lease not released")
		}
	}
}
