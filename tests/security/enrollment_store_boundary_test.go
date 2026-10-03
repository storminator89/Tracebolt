package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
)

func independentEnrollmentStoreMaterial(t *testing.T) (enrollmentstate.Config, []byte) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("private enrollment SQLite adapter is Linux-only")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral issuer fixture failed")
	}
	now := time.Unix(independentEnrollmentNow, 0)
	ca := &x509.Certificate{SerialNumber: big.NewInt(91), Subject: pkix.Name{CommonName: "Disposable independent store fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		t.Fatal("ephemeral public issuer fixture failed")
	}
	cfg := independentEnrollmentConfig()
	hash := sha256.Sum256(der)
	cfg.Binding.IssuerFingerprint = hex.EncodeToString(hash[:])
	return cfg, der
}

func independentEnrollmentStoreOpen(t *testing.T, path string, cfg enrollmentstate.Config, issuer []byte) *enrollmentstore.Store {
	t.Helper()
	s, err := enrollmentstore.Open(path, cfg, issuer)
	if err != nil {
		t.Fatal("private store open failed")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestIndependentEnrollmentStoreCrossHandleCASAndRestart(t *testing.T) {
	cfg, issuer := independentEnrollmentStoreMaterial(t)
	path := filepath.Join(t.TempDir(), "private", "enrollment.sqlite")
	one := independentEnrollmentStoreOpen(t, path, cfg, issuer)
	two := independentEnrollmentStoreOpen(t, path, cfg, issuer)
	before, err := one.CreateInvitation(context.Background(), independentEnrollmentCreate(1))
	if err != nil {
		t.Fatal(err)
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	for n, s := range []*enrollmentstore.Store{one, two} {
		wg.Add(1)
		go func(n int, s *enrollmentstore.Store) {
			defer wg.Done()
			_, err := s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{
				InvitationID: before.InvitationID, RequestID: independentEnrollmentID("request", 90+n),
				ExpectedRevision: before.Revision, Now: before.UpdatedAt + 1}, State: enrollmentstate.Canceled})
			if err == nil {
				won.Add(1)
			} else if !errors.Is(err, enrollmentstate.ErrState) && !errors.Is(err, enrollmentstate.ErrConflict) {
				t.Error("unexpected independent-handle race failure")
			}
		}(n, s)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatal("two database handles admitted conflicting CAS transitions")
	}
	after, err := two.Get(context.Background(), before.InvitationID)
	if err != nil || after.State != enrollmentstate.Canceled || after.Revision != before.Revision+1 {
		t.Fatal("second handle used stale lifecycle authority")
	}
	_ = one.Close()
	_ = two.Close()
	reopened := independentEnrollmentStoreOpen(t, path, cfg, issuer)
	got, err := reopened.Get(context.Background(), before.InvitationID)
	if err != nil || got != after {
		t.Fatal("committed tombstone changed across reopen")
	}
	if _, err := reopened.CreateInvitation(context.Background(), independentEnrollmentCreate(1)); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("old create retry revived a durable tombstone")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := reopened.CreateInvitation(ctx, independentEnrollmentCreate(2)); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled command was admitted")
	}
	if snapshots, err := reopened.Snapshots(context.Background()); err != nil || len(snapshots) != 1 {
		t.Fatal("canceled command created a durable record")
	}
}

func TestIndependentEnrollmentStoreCorruptionCannotUseCachedAuthority(t *testing.T) {
	cfg, issuer := independentEnrollmentStoreMaterial(t)
	path := filepath.Join(t.TempDir(), "private", "enrollment.sqlite")
	s := independentEnrollmentStoreOpen(t, path, cfg, issuer)
	before, err := s.CreateInvitation(context.Background(), independentEnrollmentCreate(1))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal("disposable fixture database open failed")
	}
	defer db.Close()
	// Corrupt only the test-owned database. No production path or credential is used.
	if _, err := db.Exec("UPDATE enrollment_state SET ledger=? WHERE id=1", []byte("invalid private ledger")); err != nil {
		t.Fatal("disposable ledger corruption fixture failed")
	}
	if got, err := s.Get(context.Background(), before.InvitationID); !errors.Is(err, enrollmentstore.ErrStorage) || got != (enrollmentstate.Snapshot{}) {
		t.Fatal("corrupt storage returned cached authority")
	}
	_ = s.Close()
	if reopened, err := enrollmentstore.Open(path, cfg, issuer); !errors.Is(err, enrollmentstore.ErrStorage) {
		if reopened != nil {
			_ = reopened.Close()
		}
		t.Fatal("corrupt database reopened")
	}
}

func TestIndependentEnrollmentStoreDoesNotAdoptExistingEmptyFile(t *testing.T) {
	cfg, issuer := independentEnrollmentStoreMaterial(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "existing.sqlite")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if s, err := enrollmentstore.Open(path, cfg, issuer); !errors.Is(err, enrollmentstore.ErrStorage) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal("pre-existing uninitialized file was adopted")
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatal("rejected pre-existing file was modified")
	}
}

func TestIndependentEnrollmentStoreRejectsForeignDatabaseWithoutModification(t *testing.T) {
	cfg, issuer := independentEnrollmentStoreMaterial(t)
	dir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "foreign.sqlite")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('preserve test-owned data')"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := enrollmentstore.Open(path, cfg, issuer); !errors.Is(err, enrollmentstore.ErrStorage) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal("foreign database was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected foreign database was modified")
	}
}

func TestIndependentEnrollmentTrustedLedgerIsConfigBoundAndStrict(t *testing.T) {
	cfg := independentEnrollmentConfig()
	e := independentEnrollmentEngine(t, cfg)
	if _, err := e.CreateInvitation(context.Background(), independentEnrollmentCreate(1)); err != nil {
		t.Fatal(err)
	}
	raw, err := e.EncodeTrustedLedger()
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := enrollmentstate.RestoreTrustedLedger(cfg, raw); err != nil || len(restored.Snapshots()) != 1 {
		t.Fatal("valid protected ledger roundtrip failed")
	}
	wrong := cfg
	wrong.Binding.Origin = "https://other.example"
	if _, err := enrollmentstate.RestoreTrustedLedger(wrong, raw); !errors.Is(err, enrollmentstate.ErrInvalid) {
		t.Fatal("ledger moved to a different manager origin")
	}
	wrong = cfg
	wrong.RecordLimit--
	if _, err := enrollmentstate.RestoreTrustedLedger(wrong, raw); !errors.Is(err, enrollmentstate.ErrInvalid) {
		t.Fatal("ledger silently accepted changed resource policy")
	}
	for _, altered := range [][]byte{raw[:len(raw)-1], append(append([]byte{}, raw...), 0), []byte("{}"), raw[1:]} {
		if _, err := enrollmentstate.RestoreTrustedLedger(cfg, altered); !errors.Is(err, enrollmentstate.ErrInvalid) {
			t.Fatal("ambiguous or truncated private ledger accepted")
		}
	}
}
