package customerprofiles

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	_ "modernc.org/sqlite"
)

func fixture(t *testing.T) (*Store, *sql.DB, *time.Time, enrollmentclient.CustomerProfile) {
	return fixtureAt(t, time.Now().UTC().Truncate(time.Second))
}

func fixtureAt(t *testing.T, at time.Time) (*Store, *sql.DB, *time.Time, enrollmentclient.CustomerProfile) {
	t.Helper()
	ctx := context.Background()
	now := at
	rpub, rkey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ipub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("test-root")}
	rawRoot, e := x509.CreateCertificate(rand.Reader, root, root, rpub, rkey)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rawRoot)
	if e != nil {
		t.Fatal(e)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("test-issuer")}
	rawIssuer, e := x509.CreateCertificate(rand.Reader, issuer, root, ipub, rkey)
	if e != nil {
		t.Fatal(e)
	}
	pemCert := func(raw []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	p := enrollmentclient.CustomerProfile{SchemaVersion: enrollmentclient.CustomerProfileVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Profile: "tls", EnrollmentOrigin: "https://manager.example:8443", AgentOrigin: "https://agent.example:8444", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, ServerCAPEM: pemCert(rawRoot), IssuerRootPEM: pemCert(rawRoot), IssuerPEM: pemCert(rawIssuer)}
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "profiles.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	if e = Initialize(ctx, db, p.ManagerInstanceID); e != nil {
		t.Fatal(e)
	}
	s, e := New(db, p.ManagerInstanceID)
	if e != nil {
		t.Fatal(e)
	}
	return s, db, &now, p
}

func TestRetainedHistoricalProfileAfterCertificateExpiry(t *testing.T) {
	old := time.Now().UTC().Truncate(time.Second).Add(-72 * time.Hour)
	s, db, _, p := fixtureAt(t, old)
	ctx := context.Background()
	public := raw(t, p)
	r := Record{Version: "tracebolt.customer-profile-record.v1", ManagerID: p.ManagerInstanceID, CustomerID: p.CustomerID, ProfileID: p.InstallerProfileID, PublicJSON: public, Digest: digest(public), CreatedAt: old.Unix(), ExpiresAt: old.Add(23 * time.Hour).Unix()}
	if !validRecord(r, p.ManagerInstanceID) {
		t.Fatal("historical valid record rejected")
	}
	bad := r
	bad.ExpiresAt = old.Add(25 * time.Hour).Unix()
	if validRecord(bad, p.ManagerInstanceID) {
		t.Fatal("profile outlives issuer")
	}
	body, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`INSERT INTO customer_profiles_records(profile_id,body) VALUES(?,?)`, r.ProfileID, body); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`UPDATE customer_profiles_meta SET count=1,last_at=? WHERE id=1`, r.CreatedAt); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(ctx, r.ProfileID); e != nil {
		t.Fatal("historical readback failed", e)
	}
	clock := func() time.Time { return time.Now().UTC() }
	if _, e = s.AcquireActive(ctx, r.CustomerID, r.ProfileID, clock, guard); !errors.Is(e, ErrInactive) {
		t.Fatal("expired active profile accepted", e)
	}
	// Even a historical manager clock cannot bypass the current live CA check.
	fakeClock := func() time.Time { return old.Add(time.Hour) }
	if _, e = s.AcquireActive(ctx, r.CustomerID, r.ProfileID, fakeClock, guard); !errors.Is(e, ErrInactive) {
		t.Fatal("expired actual CA admitted", e)
	}
}
func raw(t *testing.T, p enrollmentclient.CustomerProfile) []byte {
	t.Helper()
	b, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

type testAuthority struct{ check func() error }

func (a *testAuthority) Check() error { return a.check() }
func (a *testAuthority) Release()     {}

type panicAuthority struct{ releases *int }

func (a *panicAuthority) Check() error { panic("test authority panic") }
func (a *panicAuthority) Release()     { *a.releases++ }
func guard(context.Context, string, string) (AuthorityLease, error) {
	return &testAuthority{check: func() error { return nil }}, nil
}

func TestCreateLeaseRetireAndNeverReuse(t *testing.T) {
	s, db, now, p := fixture(t)
	ctx := context.Background()
	clock := func() time.Time { return *now }
	r, e := s.Create(ctx, raw(t, p), now.Add(2*time.Hour).Unix(), clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	if r.ManagerID != p.ManagerInstanceID || r.CustomerID != p.CustomerID || r.ProfileID != p.InstallerProfileID || r.Digest != digest(r.PublicJSON) {
		t.Fatal("wrong identity binding")
	}
	lease, e := s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	read, display, e := lease.Snapshot()
	if e != nil || read.Digest != r.Digest || display.ManagerInstanceID != p.ManagerInstanceID || display.IssuerFingerprint == "" {
		t.Fatal("incorrect leased snapshot", e)
	}
	read.PublicJSON[0] ^= 1
	if e = lease.Check(); e != nil {
		t.Fatal("snapshot mutated lease", e)
	}
	if e = lease.Check(); e != nil {
		t.Fatal(e)
	}
	lease.Release()
	lease.Release()
	if e = lease.Check(); !errors.Is(e, ErrInactive) {
		t.Fatal("released lease remained valid", e)
	}
	if _, e = s.Create(ctx, raw(t, p), now.Add(2*time.Hour).Unix(), clock, guard); !errors.Is(e, ErrConflict) {
		t.Fatal("duplicate accepted", e)
	}
	if _, e = s.Retire(ctx, p.CustomerID, p.InstallerProfileID, r.Digest, false, clock, guard); !errors.Is(e, ErrInvalid) {
		t.Fatal("unacknowledged retirement", e)
	}
	if _, e = s.Retire(ctx, p.CustomerID, p.InstallerProfileID, strings.Repeat("a", 64), true, clock, guard); !errors.Is(e, ErrConflict) {
		t.Fatal("wrong review accepted", e)
	}
	if _, e = s.Retire(ctx, p.CustomerID, p.InstallerProfileID, r.Digest, true, clock, guard); e != nil {
		t.Fatal(e)
	}
	if _, e = s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, guard); !errors.Is(e, ErrInactive) {
		t.Fatal("retired profile active", e)
	}
	got, e := s.Get(ctx, p.InstallerProfileID)
	if e != nil || got.RetiredAt == 0 {
		t.Fatal("retirement lost", e)
	}
	if _, e = s.Create(ctx, raw(t, p), now.Add(2*time.Hour).Unix(), clock, guard); !errors.Is(e, ErrConflict) {
		t.Fatal("retired ID reused", e)
	}
	if e = Initialize(ctx, db, p.ManagerInstanceID); !errors.Is(e, ErrStorage) {
		t.Fatal("reinitialized used state", e)
	}
}

func TestInitializeRejectsSqlitePrefixLookalike(t *testing.T) {
	db, e := sql.Open("sqlite", filepath.Join(t.TempDir(), "db"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	if _, e = db.Exec(`CREATE TABLE sqliteXfoo (a INTEGER)`); e != nil {
		t.Fatal(e)
	}
	if e = Initialize(context.Background(), db, "manager_"+strings.Repeat("1", 32)); !errors.Is(e, ErrStorage) {
		t.Fatal("nonempty database accepted", e)
	}
}

func TestActiveLeasePreventsConcurrentRetirement(t *testing.T) {
	s, _, now, p := fixture(t)
	ctx := context.Background()
	clock := func() time.Time { return *now }
	r, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	lease, e := s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() {
		_, err := s.Retire(ctx, p.CustomerID, p.InstallerProfileID, r.Digest, true, clock, guard)
		result <- err
	}()
	var early error
	finished := false
	select {
	case early = <-result:
		finished = true
		if early == nil {
			t.Fatal("retired while active lease held")
		}
	case <-time.After(100 * time.Millisecond):
	}
	if e = lease.Check(); e != nil {
		t.Fatal("active lease lost authority", e)
	}
	lease.Release()
	if !finished {
		early = <-result
	}
	if early != nil {
		if _, e = s.Retire(ctx, p.CustomerID, p.InstallerProfileID, r.Digest, true, clock, guard); e != nil {
			t.Fatal("retirement failed after release", e)
		}
	}
	if _, e = s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, guard); !errors.Is(e, ErrInactive) {
		t.Fatal("retired profile accepted", e)
	}
}

func TestAcquireActiveCleansUpOnAuthorityPanic(t *testing.T) {
	for _, mode := range []string{"acquire", "check"} {
		t.Run(mode, func(t *testing.T) {
			s, db, now, p := fixture(t)
			db.SetMaxOpenConns(1)
			ctx := context.Background()
			clock := func() time.Time { return *now }
			if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard); e != nil {
				t.Fatal(e)
			}
			releases := 0
			acquire := func(context.Context, string, string) (AuthorityLease, error) {
				if mode == "acquire" {
					panic("test acquire panic")
				}
				return &panicAuthority{releases: &releases}, nil
			}
			func() {
				defer func() {
					if recover() == nil {
						t.Error("expected panic")
					}
				}()
				_, _ = s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, acquire)
			}()
			if mode == "check" && releases != 1 {
				t.Fatalf("authority release count %d", releases)
			}
			bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if _, e := s.Get(bounded, p.InstallerProfileID); e != nil {
				t.Fatal("panic leaked profile connection or transaction", e)
			}
		})
	}
}

func TestRollbackFailureDiscardsConnection(t *testing.T) {
	s, db, now, p := fixture(t)
	db.SetMaxOpenConns(1)
	ctx := context.Background()
	clock := func() time.Time { return *now }
	if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard); e != nil {
		t.Fatal(e)
	}
	lease, e := s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	// Simulate an already ended transaction and add connection-local state.
	// Release's ROLLBACK then fails and must destroy this driver connection.
	if _, e = lease.conn.ExecContext(ctx, `ROLLBACK`); e != nil {
		t.Fatal(e)
	}
	if _, e = lease.conn.ExecContext(ctx, `CREATE TEMP TABLE rollback_failure_marker(x INTEGER)`); e != nil {
		t.Fatal(e)
	}
	lease.Release()
	var count int
	if e = db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_temp_master WHERE name='rollback_failure_marker'`).Scan(&count); e != nil {
		t.Fatal(e)
	}
	if count != 0 {
		t.Fatal("connection with uncertain transaction returned to pool")
	}
	if _, e = s.Get(ctx, p.InstallerProfileID); e != nil {
		t.Fatal("replacement connection unavailable", e)
	}
}

func TestActiveLeaseRechecksExpiryClockAndOperator(t *testing.T) {
	for _, mode := range []string{"expiry", "backward", "operator"} {
		t.Run(mode, func(t *testing.T) {
			s, _, now, p := fixture(t)
			ctx := context.Background()
			clock := func() time.Time { return *now }
			if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard); e != nil {
				t.Fatal(e)
			}
			revoked := false
			denied := errors.New("operator authority lost")
			acquire := func(context.Context, string, string) (AuthorityLease, error) {
				return &testAuthority{check: func() error {
					if revoked {
						return denied
					}
					return nil
				}}, nil
			}
			lease, e := s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, acquire)
			if e != nil {
				t.Fatal(e)
			}
			defer lease.Release()
			switch mode {
			case "expiry":
				*now = now.Add(time.Hour)
			case "backward":
				*now = now.Add(-time.Second)
			case "operator":
				revoked = true
			}
			e = lease.Check()
			if mode == "operator" && !errors.Is(e, denied) {
				t.Fatal("operator revocation missed", e)
			}
			if mode != "operator" && !errors.Is(e, ErrInactive) {
				t.Fatal("clock/expiry not rechecked", e)
			}
		})
	}
}

func TestFinalCheckTimeAdvanceAndCancellationFailClosed(t *testing.T) {
	t.Run("create expires inside final authority check", func(t *testing.T) {
		s, _, now, p := fixture(t)
		ctx := context.Background()
		clock := func() time.Time { return *now }
		count := 0
		a := func(context.Context, string, string) (AuthorityLease, error) {
			return &testAuthority{check: func() error {
				count++
				if count == 2 {
					*now = now.Add(time.Hour)
				}
				return nil
			}}, nil
		}
		if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, a); !errors.Is(e, ErrInactive) {
			t.Fatal("expired during check", e)
		}
		if _, e := s.Get(ctx, p.InstallerProfileID); !errors.Is(e, ErrInactive) {
			t.Fatal("expired create committed", e)
		}
	})
	t.Run("retire clock regresses inside final check", func(t *testing.T) {
		s, _, now, p := fixture(t)
		ctx := context.Background()
		clock := func() time.Time { return *now }
		r, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard)
		if e != nil {
			t.Fatal(e)
		}
		count := 0
		a := func(context.Context, string, string) (AuthorityLease, error) {
			return &testAuthority{check: func() error {
				count++
				if count == 2 {
					*now = now.Add(-time.Second)
				}
				return nil
			}}, nil
		}
		if _, e = s.Retire(ctx, p.CustomerID, p.InstallerProfileID, r.Digest, true, clock, a); !errors.Is(e, ErrInvalid) {
			t.Fatal("backward clock accepted", e)
		}
		got, e := s.Get(ctx, p.InstallerProfileID)
		if e != nil || got.RetiredAt != 0 {
			t.Fatal("retirement committed", e)
		}
	})
	t.Run("lease cancellation and expiry during authority check", func(t *testing.T) {
		s, _, now, p := fixture(t)
		clock := func() time.Time { return *now }
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard); e != nil {
			t.Fatal(e)
		}
		slow := false
		a := func(context.Context, string, string) (AuthorityLease, error) {
			return &testAuthority{check: func() error {
				if slow {
					*now = now.Add(time.Hour)
				}
				return nil
			}}, nil
		}
		lease, e := s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, a)
		if e != nil {
			t.Fatal(e)
		}
		slow = true
		if e = lease.Check(); !errors.Is(e, ErrInactive) {
			t.Fatal("expiry during check accepted", e)
		}
		cancel()
		if e = lease.Check(); !errors.Is(e, ErrInactive) {
			t.Fatal("canceled lease accepted", e)
		}
		lease.Release()
	})
}

func TestStrictPublicProfileAndExpiry(t *testing.T) {
	s, _, now, p := fixture(t)
	ctx := context.Background()
	clock := func() time.Time { return *now }
	good := raw(t, p)
	for _, candidate := range [][]byte{append(append([]byte(nil), good[:len(good)-1]...), []byte(`,"privateKey":"not allowed"}`)...), []byte(`{"schemaVersion":null}`), []byte(strings.Repeat("x", (64<<10)+1))} {
		if _, e := s.Create(ctx, candidate, now.Add(time.Hour).Unix(), clock, guard); !errors.Is(e, ErrInvalid) {
			t.Fatal("invalid profile accepted", e)
		}
	}
	bad := p
	bad.Profile = "http-test"
	if _, e := s.Create(ctx, raw(t, bad), now.Add(time.Hour).Unix(), clock, guard); !errors.Is(e, ErrInvalid) {
		t.Fatal("non TLS profile accepted", e)
	}
	if _, e := s.Create(ctx, good, now.Add(25*time.Hour).Unix(), clock, guard); !errors.Is(e, ErrInvalid) {
		t.Fatal("issuer expiry exceeded", e)
	}
	if _, e := s.Create(ctx, good, now.Add(time.Hour).Unix(), clock, guard); e != nil {
		t.Fatal(e)
	}
	*now = now.Add(time.Hour)
	if _, e := s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, guard); !errors.Is(e, ErrInactive) {
		t.Fatal("expired profile accepted", e)
	}
}

func TestGuardsAndClockAtCommit(t *testing.T) {
	s, _, now, p := fixture(t)
	ctx := context.Background()
	clock := func() time.Time { return *now }
	denied := errors.New("authority lost")
	n := 0
	changingCheck := func() error {
		n++
		if n == 2 {
			return denied
		}
		return nil
	}
	changing := func(context.Context, string, string) (AuthorityLease, error) {
		return &testAuthority{check: changingCheck}, nil
	}
	if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, changing); !errors.Is(e, denied) {
		t.Fatal("guard failure not propagated", e)
	}
	if _, e := s.Get(ctx, p.InstallerProfileID); !errors.Is(e, ErrInactive) {
		t.Fatal("guard failure persisted profile", e)
	}
	r, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard)
	if e != nil {
		t.Fatal(e)
	}
	deny := func(context.Context, string, string) (AuthorityLease, error) {
		return &testAuthority{check: func() error { return denied }}, nil
	}
	if _, e = s.AcquireActive(ctx, p.CustomerID, p.InstallerProfileID, clock, deny); !errors.Is(e, denied) {
		t.Fatal(e)
	}
	*now = now.Add(-time.Second)
	if _, e = s.Retire(ctx, p.CustomerID, p.InstallerProfileID, r.Digest, true, clock, guard); !errors.Is(e, ErrInvalid) {
		t.Fatal("clock rollback accepted", e)
	}
}

func TestCapacityAndMissingState(t *testing.T) {
	s, db, now, p := fixture(t)
	ctx := context.Background()
	clock := func() time.Time { return *now }
	for i := 1; i <= MaxCustomerRecords; i++ {
		p.InstallerProfileID = fmt.Sprintf("profile_%032x", i)
		if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard); e != nil {
			t.Fatal(i, e)
		}
	}
	p.InstallerProfileID = fmt.Sprintf("profile_%032x", MaxCustomerRecords+1)
	if _, e := s.Create(ctx, raw(t, p), now.Add(time.Hour).Unix(), clock, guard); !errors.Is(e, ErrLimit) {
		t.Fatal("per customer capacity missed", e)
	}
	if _, e := db.Exec(`DELETE FROM customer_profiles_records WHERE profile_id=?`, fmt.Sprintf("profile_%032x", 1)); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Get(ctx, fmt.Sprintf("profile_%032x", 2)); !errors.Is(e, ErrStorage) {
		t.Fatal("lost record not detected", e)
	}
}
