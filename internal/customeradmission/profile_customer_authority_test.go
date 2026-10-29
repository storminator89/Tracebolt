package customeradmission

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

	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerprofiles"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	_ "modernc.org/sqlite"
)

func TestProfileCustomerAuthorityZeroValueFailsClosed(t *testing.T) {
	var nilAuthority *ProfileCustomerAuthority
	for _, authority := range []*ProfileCustomerAuthority{nilAuthority, {}, {managerID: "manager_" + strings.Repeat("1", 32)}} {
		if lease, err := authority.Acquire(context.Background(), customerclaim.Metadata{ManagerID: authorityManagerID(authority)}); !errors.Is(err, ErrInvalid) || lease != nil {
			t.Fatalf("uninitialized admission authority accepted: %v", err)
		}
		if lease, err := authority.AcquireReview(context.Background(), customerclaim.Metadata{}, "", 1); !errors.Is(err, ErrInvalid) || lease != nil {
			t.Fatalf("uninitialized review authority accepted: %v", err)
		}
	}
}

func authorityManagerID(a *ProfileCustomerAuthority) string {
	if a == nil {
		return ""
	}
	return a.managerID
}

func TestProfileCustomerAuthorityAdmission(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, root, issuerPub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := func(b []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})) }
	p := enrollmentclient.CustomerProfile{SchemaVersion: enrollmentclient.CustomerProfileVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Profile: "tls", EnrollmentOrigin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, ServerCAPEM: cert(rootDER), IssuerRootPEM: cert(rootDER), IssuerPEM: cert(issuerDER)}
	rawProfile, _ := json.Marshal(p)
	_, display, err := enrollmentclient.ParseCustomerProfile(rawProfile, now)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	pendingDB, err := sql.Open("sqlite", filepath.Join(path, "pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer pendingDB.Close()
	pendingDB.SetMaxOpenConns(1)
	profileDB, err := sql.Open("sqlite", filepath.Join(path, "profile.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer profileDB.Close()
	profileDB.SetMaxOpenConns(1)
	if err = customerpending.Initialize(ctx, pendingDB); err != nil {
		t.Fatal(err)
	}
	pending, err := customerpending.New(pendingDB)
	if err != nil {
		t.Fatal(err)
	}
	if err = customerprofiles.Initialize(ctx, profileDB, p.ManagerInstanceID); err != nil {
		t.Fatal(err)
	}
	profiles, err := customerprofiles.New(profileDB, p.ManagerInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	allowProfile := func(context.Context, string, string) (customerprofiles.AuthorityLease, error) {
		return fixtureLease{check: func() error { return nil }, release: func() {}}, nil
	}
	if _, err = profiles.Create(ctx, rawProfile, now.Add(time.Hour).Unix(), clock, allowProfile); err != nil {
		t.Fatal(err)
	}
	operator, err := store.Open(filepath.Join(path, "operator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Close()
	observer, err := sql.Open("sqlite", filepath.Join(path, "operator.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	observer.SetMaxOpenConns(1)
	if _, err = observer.Exec(`PRAGMA busy_timeout=1`); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	if _, err = operator.SaveCustomer(ctx, digest, p.CustomerID, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	storageOK, managerOK := true, true
	guardCalls, loseAfter := 0, 0
	observeLock, sawLock := false, false
	storageGuard := func(context.Context) error {
		if !storageOK {
			return errors.New("storage lost")
		}
		return nil
	}
	managerGuard := func(context.Context, customerclaim.Metadata) error {
		guardCalls++
		if observeLock && guardCalls == 4 {
			if _, err := observer.Exec(`UPDATE customers SET body=body WHERE id=?`, p.CustomerID); err == nil {
				return errors.New("operator revision not locked")
			}
			sawLock = true
		}
		if !managerOK || loseAfter > 0 && guardCalls >= loseAfter {
			return errors.New("manager lost")
		}
		return nil
	}
	authority, err := NewProfileCustomerAuthority(profiles, operator, p.ManagerInstanceID, digest, clock, storageGuard, managerGuard)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"ok", "manager", "customer", "profile", "enrollment-origin", "agent-origin", "issuer", "storage", "manager-guard", "guard-lost-under-lock", "renamed"} {
		guardCalls = 0
		observeLock = name == "ok"
		b := customerchallenge.Binding{ManagerID: p.ManagerInstanceID, Origin: p.EnrollmentOrigin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: display.IssuerFingerprint}
		customer, profile := p.CustomerID, p.InstallerProfileID
		switch name {
		case "manager":
			b.ManagerID = "manager_" + strings.Repeat("7", 32)
		case "customer":
			customer = "customer_" + strings.Repeat("7", 32)
		case "profile":
			profile = "profile_" + strings.Repeat("7", 32)
		case "enrollment-origin":
			b.Origin = "https://other.example.test"
		case "agent-origin":
			b.AgentOrigin = "https://other.example.test"
		case "issuer":
			b.IssuerFingerprint = strings.Repeat("7", 64)
		case "storage":
			storageOK = false
		case "manager-guard":
			managerOK = false
		case "guard-lost-under-lock":
			guardCalls = 0
			loseAfter = 4
		case "renamed":
			if _, err = operator.SaveCustomer(ctx, digest, p.CustomerID, "Renamed", 1, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
		}
		pool, err := customerchallenge.New(b, clock)
		if err != nil {
			t.Fatal(err)
		}
		coord, err := New(pool, pending, clock, authority.Acquire)
		if err != nil {
			t.Fatal(err)
		}
		c, err := pool.Issue("192.0.2.1", customer, profile, fmt.Sprintf("claim_%032x", i+1))
		if err != nil {
			t.Fatal(err)
		}
		requestID := fmt.Sprintf("request_%032x", i+1)
		msg, err := customerclaim.SigningMessage(c, requestID, csr, now)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := customerclaim.Encode(c, requestID, csr, ed25519.Sign(key, msg), now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = coord.Submit(ctx, c.Challenge, raw)
		if (name == "ok" || name == "renamed") != (err == nil) {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "guard-lost-under-lock" && guardCalls < loseAfter {
			t.Fatal("guard was not reached under lock")
		}
		storageOK = true
		managerOK = true
		loseAfter = 0
	}
	if !sawLock {
		t.Fatal("operator lock was not verified during guard")
	}
	rows, err := pending.Records(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("unexpected admitted records: %d %v", len(rows), err)
	}
	// These review leases protect exact original pending/profile/customer state;
	// they do not themselves approve or issue anything.
	r := rows[0]
	expected := customerpending.ReviewExpectation{ManagerID: r.ManagerID, CustomerID: r.CustomerID, InstallerProfileID: r.InstallerProfileID, ClaimID: r.ClaimID, ClaimHash: r.ClaimHash, KeyFingerprint: r.KeyFingerprint, ManagerDigest: digest, CustomerRevision: 1, DeadlineAt: r.DeadlineAt}
	if lease, err := pending.AcquireReview(ctx, expected, clock, authority.AcquireReview); !errors.Is(err, store.ErrCustomerConflict) {
		if lease != nil {
			lease.Release()
		}
		t.Fatalf("stale review accepted after rename: %v", err)
	}
	expected.CustomerRevision = 2
	expected.ManagerDigest = strings.Repeat("b", 64)
	if lease, err := pending.AcquireReview(ctx, expected, clock, authority.AcquireReview); err == nil {
		lease.Release()
		t.Fatal("unreviewed manager binding accepted")
	}
	expected.ManagerDigest = digest
	expected.CustomerRevision = 0
	if lease, err := pending.AcquireReview(ctx, expected, clock, authority.AcquireReview); err == nil {
		lease.Release()
		t.Fatal("missing reviewed revision accepted")
	}
	expected.CustomerRevision = 2
	lease, err := pending.AcquireReview(ctx, expected, clock, authority.AcquireReview)
	if err != nil {
		t.Fatalf("current reviewed revision rejected: %v", err)
	}
	if err = lease.Check(); err != nil {
		t.Fatalf("current review lease invalid: %v", err)
	}
	// A competing rename cannot change the reviewed revision while the lease is
	// held. The caller must hold this lease through its own enrollment commit.
	if _, err = observer.Exec(`UPDATE customers SET body=body WHERE id=?`, p.CustomerID); err == nil {
		lease.Release()
		t.Fatal("customer mutation bypassed review lock")
	}
	renameContext, cancelRename := context.WithTimeout(ctx, 100*time.Millisecond)
	_, renameErr := operator.SaveCustomer(renameContext, digest, p.CustomerID, "Concurrent rename", 2, func() error { return nil })
	cancelRename()
	if !errors.Is(renameErr, context.DeadlineExceeded) {
		lease.Release()
		t.Fatalf("concurrent rename did not wait for review: %v", renameErr)
	}
	if err = lease.Check(); err != nil {
		lease.Release()
		t.Fatalf("failed competing rename invalidated held review: %v", err)
	}
	lease.Release()
	if _, err = operator.SaveCustomer(ctx, digest, p.CustomerID, "Renamed again", 2, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if stale, err := pending.AcquireReview(ctx, expected, clock, authority.AcquireReview); !errors.Is(err, store.ErrCustomerConflict) {
		if stale != nil {
			stale.Release()
		}
		t.Fatalf("review silently adopted renamed revision: %v", err)
	}
	// Only an independently established committed intent may use this lease.
	// The historical review is immutable, while current customer authority is held.
	original, err := pending.AcquireOriginal(ctx, expected, clock, authority.AcquireOriginal)
	if err != nil {
		t.Fatalf("original identity rejected after rename: %v", err)
	}
	if err = original.Check(); err != nil {
		original.Release()
		t.Fatal(err)
	}
	original.Release()
	managerOK = false
	if original, err = pending.AcquireOriginal(ctx, expected, clock, authority.AcquireOriginal); err == nil {
		original.Release()
		t.Fatal("revoked manager accepted")
	}
	managerOK = true
	wrong := expected
	wrong.KeyFingerprint = strings.Repeat("c", 64)
	if original, err = pending.AcquireOriginal(ctx, wrong, clock, authority.AcquireOriginal); err == nil {
		original.Release()
		t.Fatal("changed key accepted")
	}
	expected.CustomerRevision = 3
	lease, err = pending.AcquireReview(ctx, expected, clock, authority.AcquireReview)
	if err != nil {
		t.Fatalf("new explicit review rejected: %v", err)
	}
	lease.Release()
	record, err := profiles.Get(ctx, p.InstallerProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = profiles.Retire(ctx, p.CustomerID, p.InstallerProfileID, record.Digest, true, clock, allowProfile); err != nil {
		t.Fatal(err)
	}
	if original, err = pending.AcquireOriginal(ctx, expected, clock, authority.AcquireOriginal); err == nil {
		original.Release()
		t.Fatal("retired profile accepted")
	}
}
