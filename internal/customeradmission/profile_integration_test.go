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
	_ "modernc.org/sqlite"
)

// This is deliberately test-only: real operator/issuer authority, protected
// databases, database alias rejection and used markers are not implemented here.
func TestAdmissionWithRealProfileLeaseAndTestOperatorGuard(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	clock := func() time.Time { return now }
	rpub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ipub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture-root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("fixture-root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rpub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture-issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("fixture-issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, root, ipub, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := func(b []byte) string { return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})) }
	p := enrollmentclient.CustomerProfile{SchemaVersion: enrollmentclient.CustomerProfileVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Profile: "tls", EnrollmentOrigin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, ServerCAPEM: certPEM(rootDER), IssuerRootPEM: certPEM(rootDER), IssuerPEM: certPEM(issuerDER)}
	profileJSON, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	_, display, err := enrollmentclient.ParseCustomerProfile(profileJSON, now)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	pendingPath := filepath.Join(base, "pending.db")
	profilePath := filepath.Join(base, "profile.db")
	pendingDB, err := sql.Open("sqlite", pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	defer pendingDB.Close()
	pendingDB.SetMaxOpenConns(1)
	profileDB, err := sql.Open("sqlite", profilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer profileDB.Close()
	profileDB.SetMaxOpenConns(1)
	observerPending, err := sql.Open("sqlite", pendingPath)
	if err != nil {
		t.Fatal(err)
	}
	defer observerPending.Close()
	if _, err = observerPending.Exec(`PRAGMA busy_timeout=1`); err != nil {
		t.Fatal(err)
	}
	observerProfile, err := sql.Open("sqlite", profilePath)
	if err != nil {
		t.Fatal(err)
	}
	defer observerProfile.Close()
	if _, err = observerProfile.Exec(`PRAGMA busy_timeout=1`); err != nil {
		t.Fatal(err)
	}
	if err = customerpending.Initialize(ctx, pendingDB); err != nil {
		t.Fatal(err)
	}
	pending, _ := customerpending.New(pendingDB)
	if err = customerprofiles.Initialize(ctx, profileDB, p.ManagerInstanceID); err != nil {
		t.Fatal(err)
	}
	profiles, err := customerprofiles.New(profileDB, p.ManagerInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	allow := true
	testOnlyOperator := func(context.Context, string, string) (customerprofiles.AuthorityLease, error) {
		return fixtureLease{check: func() error {
			if !allow {
				return errors.New("test operator unavailable")
			}
			return nil
		}, release: func() {}}, nil
	}
	if _, err = profiles.Create(ctx, profileJSON, now.Add(time.Hour).Unix(), clock, testOnlyOperator); err != nil {
		t.Fatal(err)
	}
	operatorObservedLocks := false
	operatorUnderLocks := func(ctx context.Context, cust, profile string) (customerprofiles.AuthorityLease, error) {
		if _, e := observerPending.Exec(`UPDATE customer_pending_meta SET last_at=last_at WHERE id=1`); e == nil {
			t.Error("operator acquired before pending lock")
		}
		if _, e := observerProfile.Exec(`UPDATE customer_profiles_meta SET last_at=last_at WHERE id=1`); e == nil {
			t.Error("operator acquired before profile lock")
		}
		operatorObservedLocks = true
		return testOnlyOperator(ctx, cust, profile)
	}
	// A real adapter needs a lease implementation that verifies the active issuer
	// and operator session. This fixture compares every claim/profile binding.
	acquire := func(ctx context.Context, m customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		l, e := profiles.AcquireActive(ctx, m.CustomerID, m.InstallerProfileID, clock, operatorUnderLocks)
		if e != nil {
			return nil, e
		}
		r, d, e := l.Snapshot()
		if e != nil {
			l.Release()
			return nil, e
		}
		parsed, _, e := enrollmentclient.ParseCustomerProfile(r.PublicJSON, now)
		if e != nil || m.ManagerID != parsed.ManagerInstanceID || m.CustomerID != parsed.CustomerID || m.InstallerProfileID != parsed.InstallerProfileID || m.Origin != parsed.EnrollmentOrigin || m.AgentOrigin != parsed.AgentOrigin || m.IssuerFingerprint != d.IssuerFingerprint {
			l.Release()
			return nil, customerprofiles.ErrConflict
		}
		return l, nil
	}
	_, deviceKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	valid := customerchallenge.Binding{ManagerID: p.ManagerInstanceID, Origin: p.EnrollmentOrigin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: display.IssuerFingerprint}
	for i, caseName := range []string{"valid", "manager", "enrollment origin", "agent origin", "issuer", "customer", "profile", "operator"} {
		b := valid
		customer, profile := p.CustomerID, p.InstallerProfileID
		switch caseName {
		case "manager":
			b.ManagerID = "manager_" + strings.Repeat("7", 32)
		case "enrollment origin":
			b.Origin = "https://other.example.test"
		case "agent origin":
			b.AgentOrigin = "https://other-agent.example.test"
		case "issuer":
			b.IssuerFingerprint = strings.Repeat("7", 64)
		case "customer":
			customer = "customer_" + strings.Repeat("7", 32)
		case "profile":
			profile = "profile_" + strings.Repeat("7", 32)
		case "operator":
			allow = false
		}
		pool, e := customerchallenge.New(b, clock)
		if e != nil {
			t.Fatal(e)
		}
		coord, e := New(pool, pending, clock, acquire)
		if e != nil {
			t.Fatal(e)
		}
		id := fmt.Sprintf("claim_%032x", i+1)
		challenge, e := pool.Issue("192.0.2.1", customer, profile, id)
		if e != nil {
			t.Fatal(e)
		}
		request := fmt.Sprintf("request_%032x", i+1)
		message, e := customerclaim.SigningMessage(challenge, request, csr, now)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := customerclaim.Encode(challenge, request, csr, ed25519.Sign(deviceKey, message), now)
		if e != nil {
			t.Fatal(e)
		}
		_, e = coord.Submit(ctx, challenge.Challenge, raw)
		if caseName == "valid" && e != nil || caseName != "valid" && e == nil {
			t.Fatalf("case %s: %v", caseName, e)
		}
	}
	if !operatorObservedLocks {
		t.Fatal("operator lease not reached")
	}
	rows, err := pending.Records(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("mismatched binding admitted: %v", err)
	}
}
