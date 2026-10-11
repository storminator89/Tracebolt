package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowseventcache"
	"localrmm/internal/windowseventcontent"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowseventrequest"
	"localrmm/internal/windowseventwire"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
)

const windowsEventOperatorMessage = "synthetic-private-event-message-operator-only"
const windowsEventOperatorRecordID = "18446744073709551615"

// A deterministic trusted clock lets the real HTTP route cross a disclosure
// boundary after obtaining a page. No sleeps, host reads or native grants occur.
type windowsEventOperatorClock struct {
	mu    sync.Mutex
	at    time.Time
	calls int
	hook  func(int)
}

func (c *windowsEventOperatorClock) now() time.Time {
	c.mu.Lock()
	c.calls++
	n, hook := c.calls, c.hook
	c.mu.Unlock()
	if hook != nil {
		hook(n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}
func (c *windowsEventOperatorClock) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}
func (c *windowsEventOperatorClock) set(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = at
}
func (c *windowsEventOperatorClock) arm(hook func(int)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls, c.hook = 0, hook
}

type windowsEventOperatorFixture struct {
	operatorFixture
	service           *enrollmentservice.Service
	store             *enrollmentstore.Store
	snap              enrollmentstate.Snapshot
	capability        windowseventwire.Capability
	clock             *windowsEventOperatorClock
	authNow           *atomic.Value
	at                time.Time
	path, csrf, token string
}

// Reuse the TLS/password fixture and the inventory proof/issuer fixture pattern.
// Both separately configured authorities use one synthetic issuer, and the
// public constructor validates their exact manager/profile/bootstrap bindings.
func newWindowsEventOperatorFixture(t *testing.T) windowsEventOperatorFixture {
	t.Helper()
	return newWindowsEventOperatorFixtureFor(t, false)
}
func newWindowsEventOperatorFixtureFor(t *testing.T, named bool) windowsEventOperatorFixture {
	t.Helper()
	return newWindowsEventOperatorFixtureWithIssuerLifetime(t, named, 24*time.Hour)
}
func newWindowsEventOperatorFixtureWithIssuerLifetime(t *testing.T, named bool, issuerLifetime time.Duration, renewable ...bool) windowsEventOperatorFixture {
	t.Helper()
	o := newOperatorFixture(t, time.Hour)
	now := time.Now().UTC().Truncate(time.Second)
	clock := &windowsEventOperatorClock{at: now}
	rp, rk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic event-operator root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("event-operator-root")}
	rawRoot, err := x509.CreateCertificate(rand.Reader, rt, rt, rp, rk)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rawRoot)
	if err != nil {
		t.Fatal(err)
	}
	ip, ik, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Synthetic event-operator issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(issuerLifetime), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("event-operator-issuer")}
	rawIssuer, err := x509.CreateCertificate(rand.Reader, it, root, ip, rk)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(rawIssuer)
	issuer, err := enrollmentissuer.New(rawIssuer, rawRoot, ik, hex.EncodeToString(hash[:]), now)
	if err != nil {
		t.Fatal(err)
	}
	makeService := func(collection, name string) (*enrollmentservice.Service, *enrollmentstore.Store, EnrollmentBootstrap) {
		binding := enrollmentstate.Binding{InstanceID: "manager_" + strings.Repeat("1", 32), Profile: "tls", Origin: o.server.URL, CollectionProfile: collection, IssuerFingerprint: issuer.Fingerprint()}
		cfg := enrollmentstate.DefaultConfig(binding)
		cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
		if len(renewable) == 1 && renewable[0] {
			cfg.AutomaticRenewal = true
			cfg.RenewalAgentOrigin = o.server.URL
		}
		store, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", name+".db"), cfg, rawIssuer)
		if err != nil {
			t.Fatal("synthetic store", err)
		}
		t.Cleanup(func() { store.Close() })
		service, err := enrollmentservice.New(store, issuer, clock.now)
		if err != nil {
			t.Fatal("synthetic service", err)
		}
		t.Cleanup(service.CloseWindowsEventContent)
		asPEM := func(raw []byte) string {
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
		}
		bootstrap := EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, EnrollmentOrigin: o.server.URL, AgentOrigin: o.server.URL, CollectionProfile: collection, ServerCAPEM: asPEM(o.server.TLS.Certificates[0].Certificate[1]), IssuerRootPEM: asPEM(rawRoot), IssuerPEM: asPEM(rawIssuer)}
		if cfg.AutomaticRenewal {
			bootstrap.SchemaVersion = "tracebolt.enrollment-bootstrap.renewable.v1"
			bootstrap.RenewalPolicy = enrollmentcrypto.RenewalPolicySameKey
		}
		return service, store, bootstrap
	}
	linux, _, linuxBootstrap := makeService(enrollmentcrypto.CollectionProfile, "linux")
	service, store, windowsBootstrap := makeService(enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	if err := service.InitializeWindowsEventContent(context.Background()); err != nil {
		t.Fatal(err)
	}
	authNow := &atomic.Value{}
	authNow.Store(now)
	authConfig := operatorauth.Config{PasswordHash: testOperatorHash(), TTL: time.Hour, Now: func() time.Time { return authNow.Load().(time.Time) }}
	if named {
		authConfig.PasswordHash = ""
		authConfig.Operators = []operatorauth.Operator{{ID: namedActorID, Username: "reader", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read}}}
	}
	auth, err := operatorauth.New(authConfig)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewLANOperatorHandler(o.app, LANOperatorConfig{Origin: o.server.URL, Auth: auth, Registry: o.registry, Devices: func() ([]model.Device, error) { return []model.Device{}, nil }, Enrollment: linux, EnrollmentBootstrap: linuxBootstrap, WindowsEnrollment: service, WindowsEnrollmentBootstrap: windowsBootstrap})
	if err != nil {
		t.Fatal("configured operator boundary", err)
	}
	o.server.Config.Handler = handler
	snap := windowsEventOperatorActivate(t, service, now)
	consent := windowseventrequest.Consent{SchemaVersion: windowseventrequest.ConsentVersion, Scope: windowseventrequest.Scope, SenderBinding: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 32), Profile: "tls", Enabled: true, ContentAcknowledged: true}
	capability, err := windowseventwire.CapabilityFor(consent, windowseventrequest.LocalContext{SenderBinding: consent.SenderBinding, Profile: consent.Profile, DeviceID: snap.Approval.DeviceID, CertificateHash: snap.Issuance.CertificateHash}, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReportWindowsEventCapability(context.Background(), snap.Approval.DeviceID, snap.Issuance.CertificateHash, capability, now); err != nil {
		t.Fatal("synthetic capability", err)
	}
	windowsEventOperatorHeaders(t, store, snap, now)
	f := windowsEventOperatorFixture{operatorFixture: o, service: service, store: store, snap: snap, capability: capability, clock: clock, authNow: authNow, at: now, path: "/api/devices/" + snap.Approval.DeviceID + "/windows-event-content"}
	var login *http.Response
	var value map[string]any
	if named {
		login, value = o.call(t, "POST", "/api/auth/login", map[string]string{"username": "reader", "password": operatorFixturePassword}, "", nil)
		if login.StatusCode != http.StatusOK {
			t.Fatal("named fixture login rejected", login.StatusCode)
		}
	} else {
		login, value = o.login(t)
	}
	f.csrf = value["csrfToken"].(string)
	f.token = login.Cookies()[0].Value
	return f
}

func windowsEventOperatorActivate(t *testing.T, service *enrollmentservice.Service, now time.Time) enrollmentstate.Snapshot {
	t.Helper()
	ctx := context.Background()
	requestID := func(n string) string { return "request_" + strings.Repeat(n, 32) }
	created, err := service.CreateInvitation(ctx, requestID("1"), "windows")
	if err != nil {
		t.Fatal("fixture invitation failed", err)
	}
	invitation := created.Snapshot().InvitationID
	claimID := "claim_" + strings.Repeat("2", 32)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Synthetic Windows event operator fixture"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := service.Challenge("127.0.0.1", invitation, claimID, "claim")
	if err != nil {
		t.Fatal("fixture claim challenge failed", err)
	}
	message, err := enrollmentcrypto.ClaimSigningMessage(challenge.Context, requestID("2"), csr, created.Secret(), now)
	if err != nil {
		t.Fatal("fixture claim message failed", err)
	}
	claimBody := map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": challenge.Context.ManagerInstanceID, "profile": challenge.Context.Profile, "origin": challenge.Context.Origin, "collectionProfile": challenge.Context.CollectionProfile, "invitationId": invitation, "claimId": claimID, "requestId": requestID("2"), "challenge": challenge.Context.Challenge, "invitationSecret": created.Secret(), "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))}
	if challenge.Context.RenewalPolicy != "" {
		claimBody["schemaVersion"] = enrollmentcrypto.RenewableClaimVersion
		claimBody["renewalPolicy"] = challenge.Context.RenewalPolicy
		claimBody["agentOrigin"] = challenge.Context.AgentOrigin
	}
	raw, err := json.Marshal(claimBody)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := service.Claim(ctx, challenge.Context.Challenge, raw)
	if err != nil {
		t.Fatal("fixture claim failed", err)
	}
	if _, err := service.Approve(ctx, invitation, requestID("3"), pending.Claim.KeyFingerprint, pending.Revision); err != nil {
		t.Fatal("fixture approval failed", err)
	}
	challenge, err = service.Challenge("127.0.0.1", invitation, claimID, "status")
	if err != nil {
		t.Fatal("fixture status challenge failed", err)
	}
	publicKey, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	keyHash := sha256.Sum256(publicKey)
	message, err = enrollmentcrypto.StatusSigningMessage(challenge.Context, "status", requestID("4"), publicKey, now)
	if err != nil {
		t.Fatal("fixture status message failed", err)
	}
	raw, err = json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.StatusVersion, "managerInstanceId": challenge.Context.ManagerInstanceID, "profile": challenge.Context.Profile, "origin": challenge.Context.Origin, "collectionProfile": challenge.Context.CollectionProfile, "invitationId": invitation, "claimId": claimID, "keyFingerprint": hex.EncodeToString(keyHash[:]), "requestId": requestID("4"), "purpose": "status", "challenge": challenge.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := service.Status(ctx, challenge.Context.Challenge, raw)
	if err != nil || issued.State != enrollmentstate.Issued || issued.Intent.NotAfter <= now.Unix() {
		t.Fatal("fixture issuance failed", err)
	}
	intent := enrollmentcrypto.Intent{
		ManagerInstanceID: issued.Binding.InstanceID, Profile: issued.Binding.Profile, Origin: issued.Binding.Origin, CollectionProfile: issued.Binding.CollectionProfile,
		InvitationID: issued.InvitationID, ClaimID: issued.Claim.ClaimID, RequestID: issued.Intent.RequestID, DeviceID: issued.Approval.DeviceID, IntentID: issued.Intent.IntentID,
		KeyFingerprint: issued.Claim.KeyFingerprint, PublicKeyDERBase64: base64.RawStdEncoding.EncodeToString(publicKey), CSRHash: issued.Claim.CSRHash, ClaimHash: issued.Claim.ClaimHash,
		IssuerFingerprint: issued.Binding.IssuerFingerprint, SerialHex: issued.Intent.SerialHex, TemplateVersion: issued.Intent.TemplateVersion, KeyGeneration: 1,
		NotBefore: issued.Intent.NotBefore, NotAfter: issued.Intent.NotAfter,
	}
	challenge, err = service.Challenge("127.0.0.1", invitation, claimID, "activation")
	if err != nil {
		t.Fatal("fixture activation challenge failed", err)
	}
	message, err = enrollmentcrypto.ActivationSigningMessage(challenge.Context, intent, requestID("5"), issued.Issuance.CertificateHash, now)
	if err != nil {
		t.Fatal("fixture activation message failed", err)
	}
	raw, err = json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": challenge.Context.ManagerInstanceID, "profile": challenge.Context.Profile, "origin": challenge.Context.Origin, "deviceId": issued.Approval.DeviceID, "intentId": intent.IntentID, "certificateHash": issued.Issuance.CertificateHash, "requestId": requestID("5"), "challenge": challenge.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
	if err != nil {
		t.Fatal(err)
	}
	active, err := service.Activate(ctx, challenge.Context.Challenge, raw)
	if err != nil || active.State != enrollmentstate.Activated {
		t.Fatal("fixture activation failed", err)
	}
	return active
}

func windowsEventOperatorHeaders(t *testing.T, store *enrollmentstore.Store, identity enrollmentstate.Snapshot, at time.Time) {
	t.Helper()
	value := 42.0
	metric := model.Metric{Value: &value, Unit: "%", Quality: "healthy", Source: "Synthetic measured fixture", CollectedAt: at}
	r := windowsinventory.Report{Schema: windowsinventory.Schema, Platform: "windows", CollectedAt: at, OS: "Windows fixture", Uptime: "fixture", CPU: metric, Memory: metric, Disk: metric,
		Hostname:  windowsinventory.Section[windowsinventory.Hostname]{Source: "Fixture", Scope: "Explicit hostname scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Hostname{{Value: "fixture-windows"}}},
		Processes: windowsinventory.Section[windowsinventory.Process]{Source: "Fixture", Scope: "Bounded process scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.Process{{PID: 12, Name: "fixture.exe", Threads: 2}}},
		Services:  windowsinventory.Section[windowsinventory.Service]{Source: "Fixture", Scope: "Denied service scope", Quality: "denied", Rows: []windowsinventory.Service{}},
		Software:  windowsinventory.Section[windowsinventory.Software]{Source: "Fixture", Scope: "Partial software scope", Quality: "limited", Rows: []windowsinventory.Software{{Name: "Fixture app", Version: "1", Publisher: "Fixture", RegistryView: "64"}}},
		Network:   windowsinventory.Section[windowsinventory.InterfaceAddress]{Source: "Fixture", Scope: "Explicit interface scope", Quality: "healthy", Complete: true, Rows: []windowsinventory.InterfaceAddress{{Index: 1, Name: "Fixture", Address: "192.0.2.8", PrefixLength: 24}}}}
	snap, d, err := windowsmanaged.FromReport(r, "sample_"+strings.Repeat("1", 32))
	if err != nil {
		t.Fatal(err)
	}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "fixture", GeneratedAt: at, Platform: "windows", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	headers := windowseventhealth.Snapshot{SchemaVersion: windowseventhealth.SchemaVersion, Scope: windowseventhealth.Scope, GrantID: strings.Repeat("c", 32), GenerationID: "sample_" + strings.Repeat("1", 32), CollectedAt: at, Channels: []windowseventhealth.Channel{{Channel: "Application", Quality: "observed", Complete: true, ObservedCount: 1, Rows: []windowseventhealth.Event{{RecordID: windowsEventOperatorRecordID, EventID: 14, Level: 2, Provider: "Synthetic fixture", Timestamp: at.Add(-time.Second + 100*time.Nanosecond)}}}, {Channel: "System", Quality: "observed", Complete: true, Rows: []windowseventhealth.Event{}}}}
	raw, err := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameWindowsEventsVersion, Sequence: 1, Observation: b, WindowsInventory: &snap, WindowsEvents: &headers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SaveObservation(context.Background(), identity.InvitationID, identity.Issuance.CertificateHash, raw, at); err != nil {
		t.Fatal("synthetic header frame", err)
	}
}

func windowsEventOperatorDecode[T any](t *testing.T, value map[string]any) T {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("response encoding", err)
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal("response contract", err)
	}
	return out
}
func windowsEventOperatorNoContent(t *testing.T, response *http.Response, value map[string]any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil || strings.Contains(string(raw), windowsEventOperatorMessage) || value["report"] != nil || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("private content escaped or response became cacheable")
	}
}
func (f windowsEventOperatorFixture) status(t *testing.T) windowsEventView {
	t.Helper()
	r, v := f.call(t, "GET", f.path, nil, "", nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("status failed: %d", r.StatusCode)
	}
	windowsEventOperatorNoContent(t, r, v)
	return windowsEventOperatorDecode[windowsEventView](t, v)
}
func windowsEventOperatorCreateBody(v windowsEventView) map[string]any {
	return map[string]any{"expectedFloor": v.ExpectedFloor, "expectedHeaderGenerationId": v.Headers.GenerationID, "expectedHeaderSnapshotDigest": v.Headers.SnapshotDigest, "selections": []map[string]string{{"channel": "Application", "recordId": windowsEventOperatorRecordID}}, "acknowledgeContent": true, "acknowledgePlaintext": false}
}
func (f windowsEventOperatorFixture) create(t *testing.T) windowseventrequest.Description {
	t.Helper()
	status := f.status(t)
	if status.Headers == nil {
		t.Fatal("configured selection headers missing")
	}
	r, v := f.call(t, "POST", f.path+"/create", windowsEventOperatorCreateBody(status), f.csrf, nil)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("create failed: %d", r.StatusCode)
	}
	windowsEventOperatorNoContent(t, r, v)
	view := windowsEventOperatorDecode[windowsEventView](t, v)
	if view.Request == nil || view.Request.State != windowseventrequest.Pending || view.ContentStatus != "pending" || view.ExpectedFloor != "1" {
		t.Fatal("create did not expose the exact pending authority")
	}
	d, err := view.Request.Description.Native()
	if err != nil {
		t.Fatal("created description", err)
	}
	return d
}
func (f windowsEventOperatorFixture) accept(t *testing.T, d windowseventrequest.Description) (windowseventwire.Result, windowseventrequest.Receipt) {
	t.Helper()
	ctx := context.Background()
	peek, err := f.service.PeekWindowsEventRequest(ctx, f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, f.at)
	if err != nil || peek == nil || peek.Identity != d.Identity {
		t.Fatal("owned request did not reach endpoint cache", err)
	}
	claim, err := windowseventwire.ClaimFor(d, f.capability.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.service.ClaimWindowsEventRequest(ctx, f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, claim, f.at)
	if err != nil || grant.Description.Identity != d.Identity {
		t.Fatal("synthetic claim", err)
	}
	if _, err := f.service.ClaimWindowsEventRequest(ctx, f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, claim, f.at); !errors.Is(err, windowseventrequest.ErrConsumed) {
		t.Fatal("claim was not consume-once", err)
	}
	report := windowseventcontent.Report{Source: windowseventcontent.Source, Warning: windowseventcontent.PrivacyWarning, Quality: "observed", CollectedAt: f.at, Complete: true, Events: []windowseventcontent.Result{{Event: d.Query.Events[0], Message: windowsEventOperatorMessage, Quality: "observed", Complete: true}}}
	result := windowseventwire.Result{Claim: claim, Report: report}
	receipt, err := f.service.AcceptWindowsEventResult(ctx, f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, result, f.at)
	if err != nil || receipt.Identity != d.Identity {
		t.Fatal("synthetic acceptance", err)
	}
	return result, receipt
}
func (f windowsEventOperatorFixture) query(t *testing.T, id windowseventrequest.Identity) (*http.Response, map[string]any) {
	t.Helper()
	return f.call(t, "POST", f.path+"/query", map[string]any{"identity": id}, f.csrf, nil)
}
func (f windowsEventOperatorFixture) raw(t *testing.T, action, body, csrf string, change func(*http.Request)) (*http.Response, map[string]any) {
	t.Helper()
	return f.call(t, "POST", f.path+"/"+action, nil, csrf, func(r *http.Request) {
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		if change != nil {
			change(r)
		}
	})
}

func TestWindowsEventConfiguredOperatorTLSLifecycle(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	status := f.status(t)
	if !status.Configured || status.ExpectedFloor != "0" || status.LocalStatus != "enabled" || status.ContentStatus != "unavailable" || status.Request != nil || status.Capability == nil || !status.Capability.Enabled || status.Headers == nil || status.DeviceID != f.snap.Approval.DeviceID {
		t.Fatal("configured Windows authority not reachable")
	}
	h := f.server.Config.Handler.(*operatorHandler)
	session, err := h.auth.Lookup(f.token)
	if err != nil || status.SessionBinding != windowsEventSessionBinding(session.ID) || !status.SessionExpiresAt.Equal(session.ExpiresAt) || status.SessionBinding == f.token {
		t.Fatal("status ownership is not server-derived")
	}
	d := f.create(t)
	if d.Query.Events[0].RecordID != ^uint64(0) || !d.Query.Events[0].Timestamp.Equal(f.at.Add(-time.Second+100*time.Nanosecond)) || !d.ExpiresAt.Equal(f.at.Add(windowseventrequest.Lifetime)) {
		t.Fatal("browser description lost exact native identity or original expiry")
	}
	result, receipt := f.accept(t, d)
	status = f.status(t)
	if status.ContentStatus != "available" || status.Request == nil || status.Request.State != windowseventrequest.Accepted || status.Request.Receipt == nil || *status.Request.Receipt != receipt {
		t.Fatal("digest receipt did not expose available content metadata")
	}
	r, value := f.query(t, d.Identity)
	page := windowsEventOperatorDecode[windowseventcache.Page](t, value)
	if r.StatusCode != http.StatusOK || r.Header.Get("Cache-Control") != "no-store" || page.Identity != d.Identity || page.Receipt != receipt || len(page.Report.Events) != 1 || page.Report.Events[0].Message != windowsEventOperatorMessage || page.Report.Events[0].Event.RecordID != windowsEventOperatorRecordID || !page.Report.Events[0].Event.Timestamp.Equal(d.Query.Events[0].Timestamp) || !page.ExpiresAt.Equal(d.ExpiresAt) {
		t.Fatal("authorized query lost exact content, original expiry or browser-safe identity", r.StatusCode)
	}
	if value["identity"].(map[string]any)["sequence"] != "1" {
		t.Fatal("request sequence became a browser number")
	}
	retry, err := f.service.AcceptWindowsEventResult(context.Background(), f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, result, f.at)
	if err != nil || retry != receipt {
		t.Fatal("result retry changed committed receipt", err)
	}
	r, value = f.call(t, "POST", f.path+"/cancel", map[string]any{"identity": d.Identity}, f.csrf, nil)
	windowsEventOperatorNoContent(t, r, value)
	view := windowsEventOperatorDecode[windowsEventView](t, value)
	if r.StatusCode != http.StatusOK || view.ExpectedFloor != "1" || view.ContentStatus != "canceled" || view.Request == nil || view.Request.State != windowseventrequest.Canceled {
		t.Fatal("cancel did not retain consume-once floor", r.StatusCode)
	}
	r, value = f.query(t, d.Identity)
	windowsEventOperatorNoContent(t, r, value)
	if r.StatusCode != http.StatusConflict {
		t.Fatal("canceled content was readable", r.StatusCode)
	}
}

func TestWindowsEventConfiguredOperatorRejectsCrossSession(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	d := f.create(t)
	f.accept(t, d)
	other := f.operatorFixture
	client := *f.client
	client.Jar, _ = cookiejar.New(nil)
	other.client = &client
	_, login := other.login(t)
	otherCSRF := login["csrfToken"].(string)
	for _, action := range []string{"query", "cancel"} {
		r, value := other.call(t, "POST", f.path+"/"+action, map[string]any{"identity": d.Identity}, otherCSRF, nil)
		windowsEventOperatorNoContent(t, r, value)
		if action == "query" && r.StatusCode != http.StatusConflict || action == "cancel" && r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("other session %s status=%d", action, r.StatusCode)
		}
	}
	r, value := other.call(t, "GET", f.path, nil, "", nil)
	windowsEventOperatorNoContent(t, r, value)
	view := windowsEventOperatorDecode[windowsEventView](t, value)
	if r.StatusCode != http.StatusOK || view.ContentStatus != "result_lost" || view.SessionBinding == f.status(t).SessionBinding {
		t.Fatal("other session inherited content ownership")
	}
	r, value = other.call(t, "POST", f.path+"/create", windowsEventOperatorCreateBody(view), otherCSRF, nil)
	windowsEventOperatorNoContent(t, r, value)
	if r.StatusCode != http.StatusConflict {
		t.Fatal("another session replaced the live request", r.StatusCode)
	}
	r, value = f.query(t, d.Identity)
	if r.StatusCode != http.StatusOK || windowsEventOperatorDecode[windowseventcache.Page](t, value).Report.Events[0].Message != windowsEventOperatorMessage {
		t.Fatal("denied cross-session access destroyed original owner's content")
	}
}

func TestWindowsEventConfiguredOperatorCSRFAndExactBodies(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	body, err := json.Marshal(windowsEventOperatorCreateBody(f.status(t)))
	if err != nil {
		t.Fatal(err)
	}
	valid := string(body)
	for _, tc := range []struct {
		name, token string
		change      func(*http.Request)
		want        int
	}{
		{"missing CSRF", "", nil, 403}, {"wrong CSRF", "incorrect", nil, 403},
		{"duplicate CSRF", f.csrf, func(r *http.Request) { r.Header.Add("X-CSRF-Token", f.csrf) }, 403},
		{"missing origin", f.csrf, func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"cross origin", f.csrf, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"cross site", f.csrf, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"wrong content type", f.csrf, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, action := range []string{"create", "query", "cancel"} {
				r, value := f.raw(t, action, valid, tc.token, tc.change)
				windowsEventOperatorNoContent(t, r, value)
				if r.StatusCode != tc.want {
					t.Fatalf("%s guard status=%d want=%d", action, r.StatusCode, tc.want)
				}
			}
		})
	}
	for name, raw := range map[string]string{
		"duplicate acknowledgement":         strings.Replace(valid, `"acknowledgeContent":true`, `"acknowledgeContent":false,"acknowledgeContent":true`, 1),
		"missing acknowledgement":           strings.Replace(valid, `"acknowledgeContent":true,`, "", 1),
		"missing plaintext acknowledgement": strings.Replace(valid, `"acknowledgePlaintext":false,`, "", 1),
		"null plaintext acknowledgement":    strings.Replace(valid, `"acknowledgePlaintext":false`, `"acknowledgePlaintext":null`, 1),
		"null acknowledgement":              strings.Replace(valid, `"acknowledgeContent":true`, `"acknowledgeContent":null`, 1),
		"false acknowledgement":             strings.Replace(valid, `"acknowledgeContent":true`, `"acknowledgeContent":false`, 1),
		"case alias":                        strings.Replace(valid, `"expectedFloor"`, `"ExpectedFloor"`, 1),
		"noncanonical floor":                strings.Replace(valid, `"expectedFloor":"0"`, `"expectedFloor":"00"`, 1),
		"numeric record":                    strings.Replace(valid, `"recordId":"`+windowsEventOperatorRecordID+`"`, `"recordId":`+windowsEventOperatorRecordID, 1),
		"noncanonical record":               strings.Replace(valid, windowsEventOperatorRecordID, "0"+windowsEventOperatorRecordID, 1),
		"duplicate record":                  strings.Replace(valid, `"recordId":`, `"recordId":"2","recordId":`, 1),
		"selection alias":                   strings.Replace(valid, `"channel"`, `"Channel"`, 1),
		"selection extra":                   strings.Replace(valid, `"channel":"Application"`, `"channel":"Application","message":"injected"`, 1),
		"extra owner":                       strings.TrimSuffix(valid, "}") + `,"sessionId":"invented"}`,
		"trailing object":                   valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			r, value := f.raw(t, "create", raw, f.csrf, nil)
			windowsEventOperatorNoContent(t, r, value)
			if r.StatusCode != http.StatusBadRequest {
				t.Fatalf("ambiguous create status=%d", r.StatusCode)
			}
		})
	}
	if s := f.status(t); s.ExpectedFloor != "0" || s.Request != nil {
		t.Fatal("invalid request changed durable authority")
	}
	d := f.create(t)
	f.accept(t, d)
	identity, err := json.Marshal(map[string]any{"identity": d.Identity})
	if err != nil {
		t.Fatal(err)
	}
	valid = string(identity)
	for name, raw := range map[string]string{
		"extra owner":        strings.TrimSuffix(valid, "}") + `,"sessionId":"invented"}`,
		"identity alias":     strings.Replace(valid, `"identity"`, `"Identity"`, 1),
		"numeric sequence":   strings.Replace(valid, `"sequence":"1"`, `"sequence":1`, 1),
		"padded sequence":    strings.Replace(valid, `"sequence":"1"`, `"sequence":"01"`, 1),
		"null sequence":      strings.Replace(valid, `"sequence":"1"`, `"sequence":null`, 1),
		"duplicate sequence": strings.Replace(valid, `"sequence":"1"`, `"sequence":"2","sequence":"1"`, 1),
		"extra identity":     strings.Replace(valid, `"sequence":"1"`, `"sequence":"1","message":"injected"`, 1),
		"trailing object":    valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			for _, action := range []string{"query", "cancel"} {
				r, value := f.raw(t, action, raw, f.csrf, nil)
				windowsEventOperatorNoContent(t, r, value)
				if r.StatusCode != http.StatusBadRequest {
					t.Fatalf("ambiguous %s status=%d", action, r.StatusCode)
				}
			}
		})
	}
	if r, _ := f.query(t, d.Identity); r.StatusCode != http.StatusOK {
		t.Fatal("invalid mutations consumed or canceled the live request")
	}
}

func TestWindowsEventConfiguredOperatorFinalQueryDisclosureChecks(t *testing.T) {
	for _, tc := range []struct {
		name           string
		boundary, want int
	}{
		{"revoked certificate", -3, 409},
		{"canceled request", -3, 409},
		{"replaced grant", -3, 409},
		{"disabled grant", -3, 409},
		{"capability expires after final status", 0, 409},
		{"request expires after final status", 0, 409},
		{"certificate expires after final status", 0, 409},
		{"clock rolls back after final status", 0, 409},
		{"session expires after final status", 0, 401},
		{"logout after final status", 0, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			issuerLifetime := 24 * time.Hour
			if tc.name == "certificate expires after final status" {
				// The service caps issued certificates one second before its
				// issuer. Keep both request and capability valid at this expiry.
				issuerLifetime = 2*time.Minute + time.Second
			}
			f := newWindowsEventOperatorFixtureWithIssuerLifetime(t, false, issuerLifetime)
			d := f.create(t)
			f.accept(t, d)
			if tc.name == "request expires after final status" {
				// Renew only the existing capability's capture age. The accepted
				// request/receipt keep their original expiry and cached content.
				refreshedAt := d.ExpiresAt.Add(-time.Nanosecond)
				f.clock.set(refreshedAt)
				capability := f.capability
				capability.Sequence++
				capability.CollectedAt = refreshedAt
				if _, err := f.service.ReportWindowsEventCapability(context.Background(), f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, capability, refreshedAt); err != nil {
					t.Fatal("synthetic capability refresh", err)
				}
				if windowseventwire.CapabilityFresh(capability, d.ExpiresAt) != nil || !d.ExpiresAt.Before(time.Unix(f.snap.Intent.NotAfter, 0).UTC()) {
					t.Fatal("request expiry was not isolated from capability/certificate expiry")
				}
			}
			if tc.name == "certificate expires after final status" {
				certificateExpiry := time.Unix(f.snap.Intent.NotAfter, 0).UTC()
				if windowseventwire.CapabilityFresh(f.capability, certificateExpiry) != nil || !certificateExpiry.Before(d.ExpiresAt) {
					t.Fatal("certificate expiry was not isolated from capability/request expiry")
				}
			}
			// Prove the same authenticated query has content before the crossing and
			// locate its last trusted-clock call without relying on cache internals.
			f.clock.arm(nil)
			if r, _ := f.query(t, d.Identity); r.StatusCode != http.StatusOK {
				t.Fatal("pre-crossing content missing")
			}
			boundary := f.clock.count() + tc.boundary
			var fired atomic.Bool
			hookErrors := make(chan error, 1)
			f.clock.arm(func(n int) {
				// The final sample runs after encoding and authority reload.
				// Earlier changes occur just before that final authority reload.
				if n != boundary || !fired.CompareAndSwap(false, true) {
					return
				}
				var err error
				switch tc.name {
				case "revoked certificate":
					_, err = f.store.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: f.snap.InvitationID, RequestID: "request_" + strings.Repeat("6", 32), ExpectedRevision: f.snap.Revision, Now: f.at.Unix()}, State: enrollmentstate.Revoked})
				case "canceled request":
					err = f.store.CancelWindowsEventRequest(context.Background(), f.snap.Approval.DeviceID, d.Identity, f.at)
				case "replaced grant", "disabled grant":
					capability := f.capability
					capability.Sequence++
					if tc.name == "replaced grant" {
						capability.Consent.GrantID = strings.Repeat("d", 32)
					} else {
						capability.Consent.Enabled = false
					}
					capability.PolicyDigest, err = windowseventwire.PolicyDigest(capability.Consent)
					if err == nil {
						_, err = f.store.ReportWindowsEventCapability(context.Background(), f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, capability, f.at)
					}
				case "capability expires after final status":
					f.clock.set(f.at.Add(windowseventwire.CapabilityMaxAge))
				case "request expires after final status":
					f.clock.set(d.ExpiresAt)
				case "certificate expires after final status":
					f.clock.set(time.Unix(f.snap.Intent.NotAfter, 0).UTC())
				case "clock rolls back after final status":
					f.clock.set(f.at.Add(-time.Nanosecond))
				case "session expires after final status":
					f.authNow.Store(f.at.Add(time.Hour))
				case "logout after final status":
					f.server.Config.Handler.(*operatorHandler).auth.Logout(f.token)
				}
				hookErrors <- err
			})
			r, value := f.query(t, d.Identity)
			f.clock.arm(nil)
			windowsEventOperatorNoContent(t, r, value)
			if !fired.Load() {
				t.Fatal("final disclosure boundary was not exercised")
			}
			if err := <-hookErrors; err != nil {
				t.Fatal("synthetic authority transition", err)
			}
			if r.StatusCode != tc.want {
				t.Fatalf("late boundary leaked or returned wrong status: got=%d want=%d", r.StatusCode, tc.want)
			}
		})
	}
}

func TestWindowsEventConfiguredOperatorLogoutRevokesContentOwner(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	d := f.create(t)
	_, receipt := f.accept(t, d)
	r, value := f.call(t, "POST", "/api/auth/logout", map[string]any{}, f.csrf, nil)
	windowsEventOperatorNoContent(t, r, value)
	if r.StatusCode != http.StatusOK {
		t.Fatal("logout failed", r.StatusCode)
	}
	// Replay the old cookie explicitly; a cleared browser jar is not sufficient
	// evidence that the server revoked the original content owner's session.
	r, value = f.call(t, "POST", f.path+"/query", map[string]any{"identity": d.Identity}, f.csrf, func(r *http.Request) { r.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: f.token}) })
	windowsEventOperatorNoContent(t, r, value)
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatal("revoked session cookie still read content", r.StatusCode)
	}
	if err := f.service.MaintainWindowsEventContent(context.Background(), f.at); err != nil {
		t.Fatal("logout maintenance", err)
	}

	_, logged := f.login(t)
	f.csrf = logged["csrfToken"].(string)
	view := f.status(t)
	if view.ContentStatus != "canceled" || view.ExpectedFloor != "1" || view.Request == nil || view.Request.Receipt == nil || *view.Request.Receipt != receipt {
		t.Fatal("new session reconstructed lost content or reset authority")
	}
	r, value = f.query(t, d.Identity)
	windowsEventOperatorNoContent(t, r, value)
	if r.StatusCode != http.StatusConflict {
		t.Fatal("new session recovered the logged-out session's content", r.StatusCode)
	}
}

func TestWindowsEventConfiguredOperatorCacheLossRetryNeverRehydrates(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	d := f.create(t)
	result, receipt := f.accept(t, d)
	f.service.CloseWindowsEventContent()
	retry, err := f.service.AcceptWindowsEventResult(context.Background(), f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, result, f.at)
	if err != nil || retry != receipt {
		t.Fatal("exact accepted retry lost its original receipt", err)
	}
	view := f.status(t)
	if view.ContentStatus != "result_lost" || view.ExpectedFloor != "1" || view.Request == nil || view.Request.Receipt == nil || *view.Request.Receipt != receipt {
		t.Fatal("accepted retry reconstructed lost content or reset authority")
	}
	r, value := f.query(t, d.Identity)
	windowsEventOperatorNoContent(t, r, value)
	if r.StatusCode != http.StatusConflict {
		t.Fatal("accepted retry republished lost content", r.StatusCode)
	}
	if peek, err := f.service.PeekWindowsEventRequest(context.Background(), f.snap.Approval.DeviceID, f.snap.Issuance.CertificateHash, f.at); err != nil || peek != nil {
		t.Fatal("lost result authorized a recapture", err)
	}
}

func TestWindowsEventConfiguredNamedReadCannotAuthorizeContent(t *testing.T) {
	f := newWindowsEventOperatorFixtureFor(t, true)
	for _, route := range []struct{ method, suffix string }{{"GET", ""}, {"POST", "/create"}, {"POST", "/query"}, {"POST", "/cancel"}} {
		f.clock.arm(nil)
		response, value := f.call(t, route.method, f.path+route.suffix, map[string]any{}, f.csrf, nil)
		windowsEventOperatorNoContent(t, response, value)
		if response.StatusCode != http.StatusForbidden || f.clock.count() != 0 {
			t.Fatalf("named read reached configured content authority: method=%s suffix=%s status=%d", route.method, route.suffix, response.StatusCode)
		}
	}
	status, err := f.store.WindowsEventContentStatus(context.Background(), f.snap.Approval.DeviceID, f.at)
	if err != nil || status.ExpectedFloor != "0" || status.Request != nil {
		t.Fatal("named reader changed request authority", err)
	}
}

func TestWindowsEventConfiguredOperatorRequiresExactDisplayedSelection(t *testing.T) {
	f := newWindowsEventOperatorFixture(t)
	view := f.status(t)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   int
	}{
		{"changed floor", func(body map[string]any) { body["expectedFloor"] = "1" }, 409},
		{"changed generation", func(body map[string]any) { body["expectedHeaderGenerationId"] = "sample_" + strings.Repeat("2", 32) }, 409},
		{"changed digest", func(body map[string]any) { body["expectedHeaderSnapshotDigest"] = "sha256:" + strings.Repeat("f", 64) }, 409},
		{"unseen record", func(body map[string]any) {
			body["selections"] = []map[string]string{{"channel": "Application", "recordId": "2"}}
		}, 400},
		{"unapproved channel", func(body map[string]any) {
			body["selections"] = []map[string]string{{"channel": "Security", "recordId": windowsEventOperatorRecordID}}
		}, 400},
		{"empty selection", func(body map[string]any) { body["selections"] = []map[string]string{} }, 400},
		{"duplicate selection", func(body map[string]any) {
			body["selections"] = []map[string]string{{"channel": "Application", "recordId": windowsEventOperatorRecordID}, {"channel": "Application", "recordId": windowsEventOperatorRecordID}}
		}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := windowsEventOperatorCreateBody(view)
			tc.mutate(body)
			response, value := f.call(t, "POST", f.path+"/create", body, f.csrf, nil)
			windowsEventOperatorNoContent(t, response, value)
			if response.StatusCode != tc.want {
				t.Fatalf("inexact selection status=%d want=%d", response.StatusCode, tc.want)
			}
		})
	}
	if status := f.status(t); status.ExpectedFloor != "0" || status.Request != nil {
		t.Fatal("rejected selection changed consume-once authority")
	}
	f.create(t)
}
