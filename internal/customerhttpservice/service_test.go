package customerhttpservice

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerbudget"
	"localrmm/internal/customerchallenge"
	"localrmm/internal/customerclaim"
	"localrmm/internal/customerhttp"
	"localrmm/internal/customerpending"
	"localrmm/internal/customerprofiles"
	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/store"
	_ "modernc.org/sqlite"
)

type testLease struct{}

func (testLease) Check() error { return nil }
func (testLease) Release()     {}

type fixture struct {
	service              *Service
	handler              *customerhttp.Handler
	profiles             *customerprofiles.Store
	operator             *store.Store
	pending              *customerpending.Store
	pendingDB            *sql.DB
	p                    enrollmentclient.CustomerProfile
	digest               string
	now                  time.Time
	managerOK, storageOK bool
	budget               *customerbudget.Budget
	claimDeadline        time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Now().UTC().Truncate(time.Second), managerOK: true, storageOK: true, digest: strings.Repeat("a", 64), budget: customerbudget.New()}
	ctx := context.Background()
	clock := func() time.Time { return f.now }
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ip, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture root"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootT, rootT, rp, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fixture issuer"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuer")}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, root, ip, rk)
	if err != nil {
		t.Fatal(err)
	}
	cert := func(raw []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	}
	f.p = enrollmentclient.CustomerProfile{SchemaVersion: enrollmentclient.CustomerProfileVersion, ManagerInstanceID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Profile: "tls", EnrollmentOrigin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, ServerCAPEM: cert(rootDER), IssuerRootPEM: cert(rootDER), IssuerPEM: cert(issuerDER)}
	raw, _ := json.Marshal(f.p)
	_, display, err := enrollmentclient.ParseCustomerProfile(raw, f.now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	open := func(name string) *sql.DB {
		db, e := sql.Open("sqlite", filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.Close() })
		return db
	}
	pdb, prdb := open("pending.db"), open("profile.db")
	f.pendingDB = pdb
	if err = customerpending.Initialize(ctx, pdb); err != nil {
		t.Fatal(err)
	}
	f.pending, err = customerpending.New(pdb)
	if err != nil {
		t.Fatal(err)
	}
	if err = customerprofiles.Initialize(ctx, prdb, f.p.ManagerInstanceID); err != nil {
		t.Fatal(err)
	}
	f.profiles, err = customerprofiles.New(prdb, f.p.ManagerInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.profiles.Create(ctx, raw, f.now.Add(time.Hour).Unix(), clock, func(context.Context, string, string) (customerprofiles.AuthorityLease, error) {
		return testLease{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	f.operator, err = store.Open(filepath.Join(dir, "operator.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.operator.Close() })
	if _, err = f.operator.SaveCustomer(ctx, f.digest, f.p.CustomerID, "Customer", 0, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	storage := func(context.Context) error {
		if !f.storageOK {
			return errors.New("storage unavailable")
		}
		return nil
	}
	manager := func(ctx context.Context, _ customerclaim.Metadata) error {
		f.claimDeadline, _ = ctx.Deadline()
		if !f.managerOK {
			return errors.New("manager unavailable")
		}
		return nil
	}
	binding := customerchallenge.Binding{ManagerID: f.p.ManagerInstanceID, Origin: f.p.EnrollmentOrigin, AgentOrigin: f.p.AgentOrigin, IssuerFingerprint: display.IssuerFingerprint}
	pool, err := customerchallenge.New(binding, clock)
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = New(binding, pool, f.digest, f.profiles, f.operator, f.pending, f.budget, clock, storage, func(context.Context, ChallengeTarget) error {
		if !f.managerOK {
			return errors.New("manager unavailable")
		}
		return nil
	}, manager)
	if err != nil {
		t.Fatal(err)
	}
	f.handler, err = customerhttp.New(binding.ManagerID, binding.Origin, binding.AgentOrigin, binding.IssuerFingerprint, f.service, clock)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) send(path string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", f.p.EnrollmentOrigin+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)
	return w
}

func (f *fixture) challenge(t *testing.T, claim string) customerclaim.Context {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"customerId": f.p.CustomerID, "installerProfileId": f.p.InstallerProfileID, "claimId": claim})
	w := f.send("/v3/customer-enrollment/challenge", body)
	if w.Code != 200 {
		t.Fatalf("challenge: %d %s", w.Code, w.Body.String())
	}
	var wire struct {
		Context struct {
			ManagerID   string `json:"managerInstanceId"`
			CustomerID  string `json:"customerId"`
			ProfileID   string `json:"installerProfileId"`
			Origin      string `json:"origin"`
			AgentOrigin string `json:"agentOrigin"`
			Issuer      string `json:"issuerFingerprint"`
			ClaimID     string `json:"claimId"`
			Nonce       string `json:"challenge"`
			Expires     int64  `json:"expiresAt"`
		} `json:"context"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	c := wire.Context
	return customerclaim.Context{ManagerID: c.ManagerID, CustomerID: c.CustomerID, InstallerProfileID: c.ProfileID, Origin: c.Origin, AgentOrigin: c.AgentOrigin, IssuerFingerprint: c.Issuer, ClaimID: c.ClaimID, Challenge: c.Nonce, ExpiresAt: c.Expires}
}

func TestRealStoresHTTPFixtureClaimAndReplay(t *testing.T) {
	f := setup(t)
	c := f.challenge(t, "claim_"+strings.Repeat("4", 32))
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	id := "request_" + strings.Repeat("5", 32)
	msg, err := customerclaim.SigningMessage(c, id, csr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(c, id, csr, ed25519.Sign(key, msg), f.now)
	if err != nil {
		t.Fatal(err)
	}
	w := f.send("/v3/customer-enrollment/claim", raw)
	var result struct {
		State      string `json:"state"`
		DeadlineAt int64  `json:"deadlineAt"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.State != "pending" || result.DeadlineAt != f.now.Add(customerpending.PendingLifetime).Unix() {
		t.Fatal("pending response", w.Code, w.Body.String())
	}
	if f.claimDeadline.IsZero() || time.Until(f.claimDeadline) > 25*time.Second {
		t.Fatal("claim has no bounded internal context")
	}
	rows, err := f.pending.Records(context.Background())
	if err != nil || len(rows) != 1 || rows[0].DeadlineAt != result.DeadlineAt {
		t.Fatal("pending not committed", err)
	}
	if w = f.send("/v3/customer-enrollment/claim", raw); w.Code != 401 {
		t.Fatal("replay accepted", w.Code)
	}
}

func TestChallengeHandoffGuardAndFailure(t *testing.T) {
	for _, scenario := range []string{"success", "no guard", "guard loss", "callback panic", "guard panic", "clock expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			var retained func() error
			calls := 0
			if scenario == "guard panic" {
				f.service.managerGuard = func(context.Context, ChallengeTarget) error {
					if calls > 0 {
						panic("guard")
					}
					return nil
				}
			}
			err := f.service.WithClaimChallenge(context.Background(), "192.0.2.1", f.p.CustomerID, f.p.InstallerProfileID, "claim_"+strings.Repeat("4", 32), func(c customerclaim.Context, guard func() error) error {
				calls++
				retained = guard
				switch scenario {
				case "no guard":
					return nil
				case "guard loss":
					f.managerOK = false
					_ = guard()
					f.managerOK = true
					_ = guard()
					return nil
				case "guard panic":
					_ = guard()
					return nil
				case "callback panic":
					panic("callback")
				case "clock expiry":
					f.now = f.now.Add(time.Minute)
					_ = guard()
					return nil
				default:
					return guard()
				}
			})
			if scenario == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrUncertain) {
				t.Fatal("expected uncertain", err)
			}
			if calls != 1 {
				t.Fatal("callback count", calls)
			}
			if retained != nil && retained() == nil {
				t.Fatal("guard survived callback")
			}
			if f.budget.InUse() != 0 {
				t.Fatal("budget leaked")
			}
		})
	}
}

func TestChallengeRejectsUntrustedOrBusyBeforeHandoff(t *testing.T) {
	for _, scenario := range []string{"manager", "storage", "customer", "profile", "busy"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			customer, profile := f.p.CustomerID, f.p.InstallerProfileID
			var slots []*customerbudget.Lease
			switch scenario {
			case "manager":
				f.managerOK = false
			case "storage":
				f.storageOK = false
			case "customer":
				customer = "customer_" + strings.Repeat("a", 32)
			case "profile":
				profile = "profile_" + strings.Repeat("a", 32)
			case "busy":
				for i := 0; i < customerbudget.MaxProofs; i++ {
					l, e := f.budget.Acquire(context.Background())
					if e != nil {
						t.Fatal(e)
					}
					slots = append(slots, l)
				}
			}
			defer func() {
				for _, l := range slots {
					l.Release()
				}
			}()
			called := false
			err := f.service.WithClaimChallenge(context.Background(), "192.0.2.1", customer, profile, "claim_"+strings.Repeat("4", 32), func(customerclaim.Context, func() error) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("failed challenge handed off", err)
			}
		})
	}
}

func TestChallengeUsesLiveProfileAndCustomerLease(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.operator.SaveCustomer(ctx, f.digest, f.p.CustomerID, "Renamed", 1, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := f.service.WithClaimChallenge(ctx, "192.0.2.1", f.p.CustomerID, f.p.InstallerProfileID, "claim_"+strings.Repeat("4", 32), func(_ customerclaim.Context, guard func() error) error {
		blocked, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
		defer cancel()
		_, err := f.operator.SaveCustomer(blocked, f.digest, f.p.CustomerID, "Concurrent", 2, func() error { return nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("customer lease not held", err)
		}
		return guard()
	}); err != nil {
		t.Fatal(err)
	}
	record, err := f.profiles.Get(ctx, f.p.InstallerProfileID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.profiles.Retire(ctx, f.p.CustomerID, f.p.InstallerProfileID, record.Digest, true, func() time.Time { return f.now }, func(context.Context, string, string) (customerprofiles.AuthorityLease, error) {
		return testLease{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err = f.service.WithClaimChallenge(ctx, "192.0.2.1", f.p.CustomerID, f.p.InstallerProfileID, "claim_"+strings.Repeat("5", 32), func(customerclaim.Context, func() error) error { called = true; return nil }); err == nil || called {
		t.Fatal("retired profile issued challenge", err)
	}
}

func TestRejectsDifferentPoolBinding(t *testing.T) {
	f := setup(t)
	wrong := f.service.binding
	wrong.Origin = "https://other.example.test"
	_, err := New(wrong, f.service.pool, f.digest, f.profiles, f.operator, f.pending, f.budget, func() time.Time { return f.now }, func(context.Context) error { return nil }, func(context.Context, ChallengeTarget) error { return nil }, func(context.Context, customerclaim.Metadata) error { return nil })
	if !errors.Is(err, ErrInvalid) {
		t.Fatal("different pool binding accepted", err)
	}
}

func TestAdmitBlockedConnectionReleasesBudgetAndConsumesNonce(t *testing.T) {
	f := setup(t)
	c := f.challenge(t, "claim_"+strings.Repeat("4", 32))
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	id := "request_" + strings.Repeat("5", 32)
	msg, err := customerclaim.SigningMessage(c, id, csr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := customerclaim.Encode(c, id, csr, ed25519.Sign(key, msg), f.now)
	if err != nil {
		t.Fatal(err)
	}
	held, err := f.pendingDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	_, err = f.service.Admit(ctx, c.Challenge, raw)
	cancel()
	held.Close()
	if err == nil || f.budget.InUse() != 0 {
		t.Fatal("blocked admission did not clean up", err)
	}
	if _, err = f.service.Admit(context.Background(), c.Challenge, raw); err == nil {
		t.Fatal("timed-out claim nonce replayed")
	}
	rows, err := f.pending.Records(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatal("timed-out claim persisted", err)
	}
}
