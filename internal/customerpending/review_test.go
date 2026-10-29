package customerpending

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
)

func reviewFixture(t *testing.T) (*Store, Record, *time.Time, string) {
	t.Helper()
	ctx := context.Background()
	now := time.Unix(1790000000, 0).UTC()
	path := filepath.Join(t.TempDir(), "pending.db")
	db := openFixture(t, path)
	if err := Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	s, _ := New(db)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := proofFixture(t, now, 1, "customer_"+strings.Repeat("2", 32), "profile_"+strings.Repeat("3", 32), key, 4)
	r, err := s.Accept(ctx, p, func() time.Time { return now }, leaseFor(func() error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	return s, r, &now, path
}

func reviewExpected(r Record) ReviewExpectation {
	return ReviewExpectation{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, ClaimID: r.ClaimID, ClaimHash: r.ClaimHash, KeyFingerprint: r.KeyFingerprint, ManagerDigest: strings.Repeat("a", 64), CustomerRevision: 1, DeadlineAt: r.DeadlineAt}
}

func reviewLeaseFor(guard func() error) AcquireReviewAuthority {
	return func(context.Context, customerclaim.Metadata, string, uint64) (AuthorityLease, error) {
		return testLease{guard}, nil
	}
}

func TestReviewLeaseBindsExactIdentityAndOriginalDeadline(t *testing.T) {
	s, r, now, _ := reviewFixture(t)
	clock := func() time.Time { return *now }
	for name, mutate := range map[string]func(*ReviewExpectation){
		"manager":     func(e *ReviewExpectation) { e.ManagerID = "manager_" + strings.Repeat("9", 32) },
		"customer":    func(e *ReviewExpectation) { e.CustomerID = "customer_" + strings.Repeat("9", 32) },
		"profile":     func(e *ReviewExpectation) { e.InstallerProfileID = "profile_" + strings.Repeat("9", 32) },
		"claim":       func(e *ReviewExpectation) { e.ClaimID = "claim_" + strings.Repeat("9", 32) },
		"claim hash":  func(e *ReviewExpectation) { e.ClaimHash = strings.Repeat("a", 64) },
		"fingerprint": func(e *ReviewExpectation) { e.KeyFingerprint = strings.Repeat("b", 64) },
		"deadline":    func(e *ReviewExpectation) { e.DeadlineAt-- },
	} {
		t.Run(name, func(t *testing.T) {
			e := reviewExpected(r)
			mutate(&e)
			if l, err := s.AcquireReview(context.Background(), e, clock, reviewLeaseFor(func() error { return nil })); err == nil {
				l.Release()
				t.Fatal("different binding accepted")
			}
		})
	}
	var gotMetadata customerclaim.Metadata
	acquire := func(_ context.Context, m customerclaim.Metadata, digest string, revision uint64) (AuthorityLease, error) {
		if digest != strings.Repeat("a", 64) || revision != 1 {
			t.Fatal("review binding not passed")
		}
		gotMetadata = m
		return testLease{func() error { return nil }}, nil
	}
	l, err := s.AcquireReview(context.Background(), reviewExpected(r), clock, acquire)
	if err != nil {
		t.Fatal(err)
	}
	if gotMetadata.ExpiresAt != 0 || gotMetadata.ClaimHash != r.ClaimHash || gotMetadata.IssuerFingerprint != r.IssuerFingerprint || gotMetadata.Origin != r.Origin {
		t.Fatal("incorrect authority metadata")
	}
	copy, err := l.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	copy.PublicKeyDER[0] ^= 1
	copy, err = l.Snapshot()
	if err != nil || copy.PublicKeyDER[0] != r.PublicKeyDER[0] {
		t.Fatal("snapshot mutated original", err)
	}
	l.Release()
	l.Release()
	if l.Check() == nil {
		t.Fatal("released review usable")
	}
	*now = time.Unix(r.DeadlineAt, 0)
	if _, err = s.AcquireReview(context.Background(), reviewExpected(r), clock, acquire); !errors.Is(err, ErrExpired) {
		t.Fatal("expired record reviewed", err)
	}
}

func TestReviewRequiresExplicitCustomerRevisionAndManagerDigest(t *testing.T) {
	s, r, now, _ := reviewFixture(t)
	called := false
	acquire := func(context.Context, customerclaim.Metadata, string, uint64) (AuthorityLease, error) {
		called = true
		return testLease{func() error { return nil }}, nil
	}
	for name, mutate := range map[string]func(*ReviewExpectation){
		"missing revision": func(e *ReviewExpectation) { e.CustomerRevision = 0 },
		"unsafe revision":  func(e *ReviewExpectation) { e.CustomerRevision = 1 << 53 },
		"missing digest":   func(e *ReviewExpectation) { e.ManagerDigest = "" },
		"invalid digest":   func(e *ReviewExpectation) { e.ManagerDigest = "not-a-digest" },
	} {
		t.Run(name, func(t *testing.T) {
			called = false
			e := reviewExpected(r)
			mutate(&e)
			if lease, err := s.AcquireReview(context.Background(), e, func() time.Time { return *now }, acquire); err == nil {
				lease.Release()
				t.Fatal("unreviewed authority accepted")
			}
			if called {
				t.Fatal("invalid review reached authority")
			}
		})
	}
}

func TestReviewLeaseRechecksClockAuthorityAndContext(t *testing.T) {
	for _, scenario := range []string{"deadline", "lease limit", "clock regression", "guard", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			s, r, now, _ := reviewFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			denied := errors.New("authority revoked")
			ok := true
			l, err := s.AcquireReview(ctx, reviewExpected(r), func() time.Time { return *now }, reviewLeaseFor(func() error {
				if !ok {
					return denied
				}
				return nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer l.Release()
			switch scenario {
			case "deadline":
				*now = time.Unix(r.DeadlineAt, 0)
			case "lease limit":
				*now = now.Add(MaxReviewLease)
			case "clock regression":
				*now = now.Add(-time.Second)
			case "guard":
				ok = false
			case "cancel":
				cancel()
			}
			if err = l.Check(); err == nil {
				t.Fatal("invalidated lease accepted")
			}
			if _, err = l.Snapshot(); err == nil {
				t.Fatal("invalidated snapshot accepted")
			}
		})
	}
}

func TestReviewLockOrderReleaseAndPanic(t *testing.T) {
	s, r, now, path := reviewFixture(t)
	second := openFixture(t, path)
	clock := func() time.Time { return *now }
	acquire := func(ctx context.Context, m customerclaim.Metadata, _ string, _ uint64) (AuthorityLease, error) {
		// Zero busy timeout makes a second writer fail without hanging the test.
		if _, err := second.ExecContext(ctx, `BEGIN IMMEDIATE`); err == nil {
			second.ExecContext(ctx, `ROLLBACK`)
			t.Fatal("authority acquired before pending lock")
		}
		return testLease{func() error { return nil }}, nil
	}
	l, err := s.AcquireReview(context.Background(), reviewExpected(r), clock, acquire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = second.Exec(`BEGIN IMMEDIATE`); err == nil {
		second.Exec(`ROLLBACK`)
		t.Fatal("review did not hold pending lock")
	}
	l.Release()
	if _, err = second.Exec(`BEGIN IMMEDIATE`); err != nil {
		t.Fatal("review did not release lock", err)
	}
	if _, err = second.Exec(`ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected panic")
			}
		}()
		s.AcquireReview(context.Background(), reviewExpected(r), clock, func(context.Context, customerclaim.Metadata, string, uint64) (AuthorityLease, error) {
			panic("synthetic")
		})
	}()
	if _, err = second.Exec(`BEGIN IMMEDIATE`); err != nil {
		t.Fatal("panic leaked lock", err)
	}
	second.Exec(`ROLLBACK`)
}

func TestReviewAcquireFailuresReleaseInOrder(t *testing.T) {
	for _, scenario := range []string{"error", "check panic", "guard passes deadline"} {
		t.Run(scenario, func(t *testing.T) {
			s, r, now, path := reviewFixture(t)
			second := openFixture(t, path)
			released := false
			denied := errors.New("denied")
			acquire := func(context.Context, customerclaim.Metadata, string, uint64) (AuthorityLease, error) {
				if scenario == "error" {
					return nil, denied
				}
				return trackingLease{check: func() error {
					if scenario == "check panic" {
						panic("synthetic guard panic")
					}
					*now = time.Unix(r.DeadlineAt, 0)
					return nil
				}, release: func() {
					released = true
					// Pending must already have been released before nested authority.
					if _, err := second.Exec(`BEGIN IMMEDIATE`); err != nil {
						t.Error("nested lease released before pending lock", err)
						return
					}
					_, _ = second.Exec(`ROLLBACK`)
				}}, nil
			}
			if scenario == "check panic" {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("missing panic")
						}
					}()
					_, _ = s.AcquireReview(context.Background(), reviewExpected(r), func() time.Time { return *now }, acquire)
				}()
			} else if _, err := s.AcquireReview(context.Background(), reviewExpected(r), func() time.Time { return *now }, acquire); err == nil {
				t.Fatal("invalid authority accepted")
			}
			if scenario != "error" && !released {
				t.Fatal("authority not released")
			}
			if _, err := second.Exec(`BEGIN IMMEDIATE`); err != nil {
				t.Fatal("pending lock leaked", err)
			}
			_, _ = second.Exec(`ROLLBACK`)
		})
	}
}
