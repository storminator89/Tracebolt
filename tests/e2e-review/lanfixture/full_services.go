// Synthetic complete-service rows through the real enrollment ledger and operator
// API. Compiled only into this loopback QA fixture, never the manager executable.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsfullservices"
)

func fsMust(e error) {
	if e != nil {
		panic(e)
	}
}
func fsID(prefix string) string {
	b := make([]byte, 16)
	_, e := rand.Read(b)
	fsMust(e)
	return prefix + hex.EncodeToString(b)
}
func fsJSON(v any) []byte { b, e := json.Marshal(v); fsMust(e); return b }

type fullServicesInfo struct {
	DeviceID    string `json:"deviceId"`
	FirstName   string `json:"firstName"`
	LaterName   string `json:"laterName"`
	LaterSearch string `json:"laterSearch"`
	RowCount    int    `json:"rowCount"`
}
type fullServicesFixture struct {
	mu       sync.Mutex
	service  *enrollmentservice.Service
	store    *enrollmentstore.Store
	basic    *enrollmentstore.Store
	offset   atomic.Int64
	snap     enrollmentstate.Snapshot
	consent  windowsfullservices.Consent
	sequence uint64
	info     fullServicesInfo
	origin   string
}

func (f *fullServicesFixture) now() time.Time {
	return time.Now().UTC().Add(time.Duration(f.offset.Load()))
}
func (f *fullServicesFixture) close() {
	if f.store != nil {
		f.store.Close()
	}
	if f.basic != nil {
		f.basic.Close()
	}
}
func fullServicesIssuer(now time.Time) (*enrollmentissuer.Issuer, error) {
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	defer clear(rk)
	ip, ik, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	rh, ih := sha256.Sum256(rp), sha256.Sum256(ip)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable browser fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		return nil, e
	}
	root, e = x509.ParseCertificate(rd)
	if e != nil {
		return nil, e
	}
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable browser fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	der, e := x509.CreateCertificate(rand.Reader, intermediate, root, ip, rk)
	if e != nil {
		return nil, e
	}
	fp := sha256.Sum256(der)
	return enrollmentissuer.New(der, rd, ik, hex.EncodeToString(fp[:]), now)
}

func (f *fullServicesFixture) seed(active bool) enrollmentstate.Snapshot {
	ctx := context.Background()
	created, e := f.service.CreateInvitation(ctx, fsID("request_"), "windows")
	fsMust(e)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	fsMust(e)
	defer clear(key)
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Invented browser fixture"}}, key)
	fsMust(e)
	claimID := fsID("claim_")
	c, e := f.service.Challenge("127.0.0.1", created.Snapshot().InvitationID, claimID, "claim")
	fsMust(e)
	request := fsID("request_")
	message, e := enrollmentcrypto.ClaimSigningMessage(c.Context, request, csr, created.Secret(), f.now())
	fsMust(e)
	common := func(c enrollmentservice.Challenge) map[string]string {
		return map[string]string{"managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": c.Context.InvitationID, "claimId": c.Context.ClaimID, "challenge": c.Context.Challenge}
	}
	body := common(c)
	body["schemaVersion"] = enrollmentcrypto.ClaimVersion
	body["requestId"] = request
	body["invitationSecret"] = created.Secret()
	body["csr"] = base64.RawStdEncoding.EncodeToString(csr)
	body["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))
	raw := fsJSON(body)
	s, e := f.service.Claim(ctx, c.Context.Challenge, raw)
	clear(raw)
	delete(body, "invitationSecret")
	fsMust(e)
	s, e = f.service.Approve(ctx, s.InvitationID, fsID("request_"), s.Claim.KeyFingerprint, s.Revision)
	fsMust(e)
	if !active {
		return s
	}
	c, e = f.service.Challenge("127.0.0.1", s.InvitationID, claimID, "status")
	fsMust(e)
	der, e := x509.MarshalPKIXPublicKey(key.Public())
	fsMust(e)
	fp := sha256.Sum256(der)
	request = fsID("request_")
	message, e = enrollmentcrypto.StatusSigningMessage(c.Context, "status", request, der, f.now())
	fsMust(e)
	body = common(c)
	body["schemaVersion"] = enrollmentcrypto.StatusVersion
	body["purpose"] = "status"
	body["requestId"] = request
	body["keyFingerprint"] = hex.EncodeToString(fp[:])
	body["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))
	s, e = f.service.Status(ctx, c.Context.Challenge, fsJSON(body))
	fsMust(e)
	cert, e := f.store.CertificateForVerification(ctx, s.InvitationID)
	fsMust(e)
	c, e = f.service.Challenge("127.0.0.1", s.InvitationID, claimID, "activation")
	fsMust(e)
	request = fsID("request_")
	message, e = enrollmentcrypto.ActivationSigningMessage(c.Context, cert.Intent(), request, cert.CertificateHash(), f.now())
	fsMust(e)
	body = map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "deviceId": cert.Intent().DeviceID, "intentId": cert.Intent().IntentID, "certificateHash": cert.CertificateHash(), "requestId": request, "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))}
	s, e = f.service.Activate(ctx, c.Context.Challenge, fsJSON(body))
	fsMust(e)
	return s
}

func newFullServicesFixture(origin, dir string, config *api.LANOperatorConfig) (f *fullServicesFixture, err error) {
	f = &fullServicesFixture{origin: origin}
	f.offset.Store(-int64(windowsfullservices.Retention))
	defer func() {
		if recover() != nil {
			f.close()
			f = nil
			err = errors.New("complete-services fixture initialization failed")
		}
	}()
	issuer, e := fullServicesIssuer(f.now())
	fsMust(e)
	makeService := func(profile, name string) (*enrollmentservice.Service, *enrollmentstore.Store, api.EnrollmentBootstrap) {
		binding := enrollmentstate.Binding{InstanceID: "manager_" + strings.Repeat("1", 32), Profile: "http-test", Origin: origin, CollectionProfile: profile, IssuerFingerprint: issuer.Fingerprint()}
		cfg := enrollmentstate.DefaultConfig(binding)
		cfg.RecordLimit = 25
		cfg.InvitationLimit = 25
		cfg.PendingLimit = 25
		st, e := enrollmentstore.Open(filepath.Join(dir, name, "state.db"), cfg, issuer.IssuerDER())
		fsMust(e)
		svc, e := enrollmentservice.New(st, issuer, f.now)
		fsMust(e)
		asPEM := func(raw []byte) string {
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
		}
		return svc, st, api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, EnrollmentOrigin: origin, AgentOrigin: origin, CollectionProfile: profile, IssuerRootPEM: asPEM(issuer.RootDER()), IssuerPEM: asPEM(issuer.IssuerDER())}
	}
	config.Enrollment, f.basic, config.EnrollmentBootstrap = makeService(enrollmentcrypto.CollectionProfile, "full-services-basic")
	f.service, f.store, config.WindowsEnrollmentBootstrap = makeService(enrollmentcrypto.CollectionProfileWindowsInventory, "full-services-windows")
	config.WindowsEnrollment = f.service
	fsMust(f.service.InitializeWindowsFullServices(context.Background()))
	f.snap = f.seed(true)
	f.consent = windowsfullservices.Consent{SchemaVersion: windowsfullservices.ConsentVersion, Scope: windowsfullservices.Scope, SenderBinding: windowsfullservices.SenderBinding("http-test", origin, f.snap.Issuance.CertificateHash, f.snap.Approval.DeviceID), GrantID: strings.TrimPrefix(fsID("grant_"), "grant_"), Revision: 1, Enabled: true, ChangedAt: f.now()}
	fsMust(f.apply(windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent}))
	f.offset.Store(0) // Remaining operations, sessions and expiry use the real clock.
	fsMust(f.sample("replace"))
	config.Devices = func() ([]model.Device, error) {
		rows, e := f.service.Devices(context.Background(), f.now())
		for i := range rows {
			rows[i].Name = "Synthetic complete Win32 service fixture"
		}
		return rows, e
	}
	return f, nil
}
func (f *fullServicesFixture) apply(m windowsfullservices.Message) error {
	raw, e := windowsfullservices.EncodeMessage(m)
	if e != nil {
		return e
	}
	ctx := enrollmentstore.WithWindowsFullServicesIngressOrigin(context.Background(), f.origin)
	_, e = f.service.ApplyWindowsFullServices(ctx, f.snap.InvitationID, f.snap.Issuance.CertificateHash, m, raw, f.now())
	return e
}
func (f *fullServicesFixture) sample(kind string) error {
	// Browser phases run faster than the real background cadence. Exercise the
	// same bounded maintenance entrypoint, never delete rows or relax quotas.
	for i := 0; i < 64; i++ {
		if e := f.service.MaintainWindowsFullServices(context.Background(), f.now()); e != nil {
			return e
		}
	}
	f.sequence++
	now := f.now()
	if kind == "fail" {
		return f.apply(windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "failure", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent, Sequence: f.sequence, AttemptedAt: &now, Reason: "access_denied"})
	}
	count := 2051
	if kind == "near-expiry" {
		// Expiry has its own one-row generation to separate its short original
		// lifetime from bulk-ingest cost. Bulk phases keep all 2,051 rows.
		count = 1
	}
	if kind == "empty" {
		count = 0
	}
	if kind == "byte-short" {
		count = 128
	}
	rows := make([]windowsfullservices.Row, count)
	for i := range rows {
		name := fmt.Sprintf("InventedService%05d", i)
		display := fmt.Sprintf("Synthetic Win32 display %05d 東京", i)
		state := "running"
		pid := uint32(i + 300)
		if i == 2049 {
			display = "Later2049 東京 <script>literal</script>"
		}
		if kind == "byte-short" {
			name = fmt.Sprintf("%04d", i) + strings.Repeat("<", 252)
			display = strings.Repeat("<", 256)
		}
		rows[i] = windowsfullservices.Row{Name: name, DisplayName: &display, DisplayNameQuality: "observed", State: &state, StateQuality: "observed", PID: &pid, PIDQuality: "observed"}
	}
	captureAt := now
	if kind == "near-expiry" {
		captureAt = now.Add(-windowsfullservices.Retention + 7*time.Second)
	}
	messages, e := windowsfullservices.Build(f.snap.Approval.DeviceID, f.consent, f.sequence, windowsfullservices.Capture{StartedAt: captureAt, FinishedAt: captureAt, Rows: rows, Complete: true})
	if e != nil {
		return e
	}
	for _, m := range messages {
		if e = f.apply(m); e != nil {
			return e
		}
	}
	f.info = fullServicesInfo{DeviceID: f.snap.Approval.DeviceID, RowCount: count, LaterSearch: "Later2049 東京"}
	if count > 0 {
		f.info.FirstName = rows[0].Name
		f.info.LaterName = rows[len(rows)-1].Name
		if count > 2049 {
			f.info.LaterName = rows[2049].Name
		}
	}
	return nil
}
func (f *fullServicesFixture) action(action string) error {
	switch action {
	case "replace", "fail", "byte-short", "empty", "near-expiry":
		return f.sample(action)
	case "disable", "enable":
		enabled := action == "enable"
		if f.consent.Enabled == enabled {
			return errors.New("unexpected fixture phase")
		}
		f.consent.Revision++
		f.consent.Enabled = enabled
		f.consent.ChangedAt = f.now()
		if enabled {
			f.consent.GrantID = strings.TrimPrefix(fsID("grant_"), "grant_")
		}
		if e := f.apply(windowsfullservices.Message{SchemaVersion: windowsfullservices.MessageVersion, Operation: "scope", DeviceID: f.snap.Approval.DeviceID, Consent: f.consent}); e != nil {
			return e
		}
		if enabled {
			return f.sample("replace")
		}
		return nil
	case "revoke":
		_, e := f.service.Terminate(context.Background(), f.snap.InvitationID, fsID("request_"), f.snap.Revision, enrollmentstate.Revoked)
		return e
	}
	return errors.New("unknown fixture action")
}
func (f *fullServicesFixture) handler(next http.Handler, auth *operatorauth.Manager) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__fixture/windows-full-services" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		host, _, e := net.SplitHostPort(r.RemoteAddr)
		if e != nil || host != "127.0.0.1" || r.Host != strings.TrimPrefix(f.origin, "http://") || r.URL.RawQuery != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "fixture request rejected", 403)
			return
		}
		cookie, e := r.Cookie("tracebolt-http-test-session")
		if e != nil {
			http.Error(w, "fixture session required", 401)
			return
		}
		session, e := auth.Lookup(cookie.Value)
		if e != nil {
			http.Error(w, "fixture session required", 401)
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == "POST" {
			if r.Header.Get("Origin") != f.origin || len(r.Header.Values("X-CSRF-Token")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(session.CSRFToken)) != 1 {
				http.Error(w, "fixture authorization required", 403)
				return
			}
			raw, e := io.ReadAll(io.LimitReader(r.Body, 257))
			var action struct {
				Action string `json:"action"`
			}
			if e != nil || len(raw) > 256 || json.Unmarshal(raw, &action) != nil || string(fsJSON(action)) != string(raw) {
				http.Error(w, "fixture action rejected", 400)
				return
			}
			release, e := session.BeginMutation(r.Context())
			if e != nil {
				w.WriteHeader(401)
				return
			}
			defer release()
			if e = f.action(action.Action); e != nil {
				http.Error(w, "fixture action failed", 400)
				return
			}
		}
		if _, e = auth.Lookup(cookie.Value); e != nil {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(f.info)
	})
}
