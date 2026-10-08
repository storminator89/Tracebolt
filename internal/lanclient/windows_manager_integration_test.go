//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"localrmm/internal/api"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/enrollmenttransport"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/operatorauth"
	"localrmm/internal/signedhttp"
	appstore "localrmm/internal/store"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsinventory"
	"localrmm/internal/windowsmanaged"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsvolumes"
)

// These are Linux-hosted integration fixtures, not Windows native acceptance.
// Keys live in memory, stores live in disposable test directories, and requests
// go directly through ServeHTTP. No listener, OS collector, service, or grant is
// created. The private sender seam deliberately bypasses the native OS gate.
type windowsManagerFixture struct {
	store    *enrollmentstore.Store
	path     string
	config   enrollmentstate.Config
	issuer   *enrollmentissuer.Issuer
	identity enrollmentstate.Snapshot
	material Material
	ingress  *enrollmenttransport.Ingress
}

func windowsManagerID(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }

func newWindowsManagerFixture(t *testing.T, collection, platform string) *windowsManagerFixture {
	return newWindowsManagerFixtureForTransport(t, collection, platform, "http-test")
}

// The transport-specific fixture uses in-memory certificates and injected requests, never a listener.
func newWindowsManagerFixtureForTransport(t *testing.T, collection, platform, transport string) *windowsManagerFixture {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	newKey := func() (ed25519.PublicKey, ed25519.PrivateKey) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return pub, key
	}
	makeCert := func(template, parent *x509.Certificate, pub ed25519.PublicKey, signer ed25519.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	rp, rk := newKey()
	ip, ik := newKey()
	rh, ih := sha256.Sum256(rp), sha256.Sum256(ip)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Invented integration root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	root := makeCert(rt, rt, rp, rk)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Invented integration issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	issuerCert := makeCert(it, root, ip, rk)
	fingerprint := sha256.Sum256(issuerCert.Raw)
	issuer, err := enrollmentissuer.New(issuerCert.Raw, root.Raw, ik, hex.EncodeToString(fingerprint[:]), now)
	if err != nil {
		t.Fatal(err)
	}
	origin := "http://fixture.invalid"
	if transport == "tls" {
		origin = "https://fixture.invalid"
	}
	config := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: windowsManagerID("manager", 1), Origin: origin, Profile: transport, CollectionProfile: collection, IssuerFingerprint: issuer.Fingerprint()})
	config.RecordLimit, config.InvitationLimit, config.PendingLimit = 25, 25, 25
	f := &windowsManagerFixture{path: filepath.Join(t.TempDir(), "manager", "enrollment.sqlite"), config: config, issuer: issuer}
	f.open(t)
	t.Cleanup(func() { _ = f.store.Close() })
	_, agentKey := newKey()
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{32}, 32))
	secretHash, err := enrollmentcrypto.InvitationHash(secret)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.store.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: windowsManagerID("invite", 1), RequestID: windowsManagerID("request", 1), InvitationHash: hex.EncodeToString(secretHash[:]), Platform: platform, Now: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	control := func(n int) enrollmentstate.Control {
		return enrollmentstate.Control{InvitationID: f.identity.InvitationID, RequestID: windowsManagerID("request", n), ExpectedRevision: f.identity.Revision, Now: now.Unix()}
	}
	challenge := enrollmentcrypto.ChallengeContext{ManagerInstanceID: config.Binding.InstanceID, Profile: config.Binding.Profile, Origin: config.Binding.Origin, CollectionProfile: collection, InvitationID: f.identity.InvitationID, ClaimID: windowsManagerID("claim", 1), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{77}, 32)), ExpiresAt: now.Unix() + 60}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, agentKey)
	if err != nil {
		t.Fatal(err)
	}
	message, err := enrollmentcrypto.ClaimSigningMessage(challenge, control(2).RequestID, csr, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	raw := windowsManagerJSON(t, map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": challenge.ManagerInstanceID, "profile": challenge.Profile, "origin": challenge.Origin, "collectionProfile": collection, "invitationId": challenge.InvitationID, "claimId": challenge.ClaimID, "requestId": control(2).RequestID, "challenge": challenge.Challenge, "invitationSecret": secret, "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(agentKey, message))})
	claim, err := enrollmentcrypto.VerifyClaim(raw, challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.store.Claim(ctx, enrollmentstate.ClaimCommand{Control: control(2), ClaimID: challenge.ClaimID}, claim)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.store.Approve(ctx, enrollmentstate.ApproveCommand{Control: control(3), DeviceID: windowsManagerID("agent", 1), KeyFingerprint: claim.KeyFingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.store.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: control(4), IntentID: windowsManagerID("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: now.Unix() - 30, NotAfter: now.Add(7 * 24 * time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := f.store.SigningIntent(ctx, f.identity.InvitationID, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	cert, err := issuer.Sign(ctx, intent, now)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.store.CommitIssued(ctx, control(5), cert)
	if err != nil {
		t.Fatal(err)
	}
	message, err = enrollmentcrypto.ActivationSigningMessage(challenge, intent, control(6).RequestID, cert.CertificateHash(), now)
	if err != nil {
		t.Fatal(err)
	}
	raw = windowsManagerJSON(t, map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": intent.ManagerInstanceID, "profile": intent.Profile, "origin": intent.Origin, "deviceId": intent.DeviceID, "intentId": intent.IntentID, "certificateHash": cert.CertificateHash(), "requestId": control(6).RequestID, "challenge": challenge.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(agentKey, message))})
	proof, err := enrollmentcrypto.VerifyActivation(raw, cert, challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.store.Activate(ctx, control(6), proof)
	if err != nil || f.identity.State != enrollmentstate.Activated {
		t.Fatal("fixture activation failed", err)
	}
	f.material = windowsMaterialFixture(t, transport)
	f.material.certificate = tls.Certificate{Certificate: [][]byte{cert.DER(), issuer.IssuerDER()}, PrivateKey: agentKey}
	f.material.config.AgentID, f.material.config.ManagerOrigin = intent.DeviceID, config.Binding.Origin
	leaf, err := x509.ParseCertificate(cert.DER())
	if err != nil {
		t.Fatal(err)
	}
	binding := senderBinding(f.material.config, leaf)
	f.material.binding = hex.EncodeToString(binding[:])
	if !f.material.valid() {
		t.Fatal("enrolled fixture material is invalid")
	}
	return f
}

func (f *windowsManagerFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.store, err = enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	f.ingress, err = enrollmenttransport.New(f.store, f.issuer.IssuerDER(), f.config.Binding.Origin)
	if err != nil {
		t.Fatal(err)
	}
}

func windowsManagerJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *windowsManagerFixture) request(t *testing.T, path string, body []byte) *http.Request {
	t.Helper()
	var frame frame
	if err := json.Unmarshal(body, &frame); err != nil {
		t.Fatal(err)
	}
	r, err := signedhttp.NewSignedRequestForPath(context.Background(), f.config.Binding.Origin, path, f.material.certificate, frame.Sequence, frame.Observation.GeneratedAt, body)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *windowsManagerFixture) serve(t *testing.T, r *http.Request, wantStatus int) *http.Response {
	t.Helper()
	w := httptest.NewRecorder()
	f.ingress.ServeHTTP(w, r)
	if w.Code != wantStatus {
		t.Fatalf("synthetic ingress status = %d, want %d", w.Code, wantStatus)
	}
	return w.Result()
}

func (f *windowsManagerFixture) view(t *testing.T, now time.Time) enrollmentstore.WindowsInventoryView {
	t.Helper()
	v, err := f.store.WindowsInventoryView(context.Background(), f.identity.Approval.DeviceID, now)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestWindowsManagerPipelineRetryRestartAndLatestView(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	if v := f.view(t, time.Now().UTC()); v.Status != "awaiting" || v.Snapshot != nil || v.Sequence != nil {
		t.Fatal("activated identity must await its first report")
	}
	var reports []windowsinventory.Report
	var snapshots []windowsmanaged.Snapshot
	collect := func(_ context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
		r := syntheticWindowsReport(time.Now().UTC())
		memory, disk := 41.5, 24.25
		r.Memory.Value, r.Memory.Quality = &memory, "healthy"
		r.Disk.Value, r.Disk.Quality = &disk, "healthy"
		r.Services.Quality, r.Services.Complete = "healthy", true
		r.Services.Rows = []windowsinventory.Service{{Name: "InventedService", DisplayName: "Invented Service", State: "running", PID: 7}}
		r.Software.Quality = "limited"
		r.Software.Rows = []windowsinventory.Software{{Name: "Invented Software", Version: "1.0", Publisher: "Fixture", RegistryView: "64"}}
		if len(reports) > 0 {
			r.Processes.Quality, r.Processes.Complete = "denied", false
			r.Processes.Rows = []windowsinventory.Process{}
		}
		s, d, err := windowsmanaged.FromReport(r, generation)
		reports, snapshots = append(reports, r), append(snapshots, s)
		return s, d, err
	}
	var bodies [][]byte
	var signatures []string
	var receipts []lanstore.Receipt
	send := func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != signedhttp.WindowsPath {
			t.Fatal("Windows sender used a Linux path")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(raw))
		bodies, signatures = append(bodies, bytes.Clone(raw)), append(signatures, r.Header.Get(signedhttp.SignatureHeader))
		response := f.serve(t, r, http.StatusOK)
		encoded, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		var receipt lanstore.Receipt
		if err := json.Unmarshal(encoded, &receipt); err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, receipt)
		if len(receipts) == 1 {
			return nil, errors.New("synthetic lost response after manager commit")
		}
		response.Body = io.NopCloser(bytes.NewReader(encoded))
		return response, nil
	}
	first, err := runUsingStateWithDependencies(ctx, f.material, state, nil, nil, nil, collect, send)
	if !errors.Is(err, ErrTransport) || first.Sequence != 1 || len(reports) != 1 || receipts[0].Duplicate {
		t.Fatal("lost response failed to leave one committed report and one pending frame", err)
	}
	pending, err := state.Pending()
	if err != nil || pending == nil || pending.Sequence != 1 || !bytes.Equal(pending.Body(), bodies[0]) {
		t.Fatal("sender did not durably retain its exact sent bytes", err)
	}
	pendingDigest := pending.Digest
	before := f.view(t, time.Now().UTC())
	if before.Status != "fresh" || before.DeviceID != f.identity.Approval.DeviceID || before.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || before.Sequence == nil || *before.Sequence != 1 || before.ReceivedAt == nil || !before.ReceivedAt.Equal(receipts[0].ReceivedAt) || !reflect.DeepEqual(before.Snapshot, &snapshots[0]) {
		t.Fatal("source report was not persisted under its approved Windows identity")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	state, err = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	pending, err = state.Pending()
	if err != nil || pending == nil || pending.Digest != pendingDigest || !bytes.Equal(pending.Body(), bodies[0]) {
		t.Fatal("restart changed the pending frame", err)
	}
	second, err := runUsingStateWithDependencies(ctx, f.material, state, nil, nil, nil, collect, send)
	if err != nil || second.Sequence != 1 || !second.RetriedPending || !second.Duplicate || len(reports) != 1 || !bytes.Equal(bodies[0], bodies[1]) || signatures[0] == "" || signatures[0] != signatures[1] {
		t.Fatal("restart retry recollected or changed exact signed request", err)
	}
	if !receipts[1].ReceivedAt.Equal(receipts[0].ReceivedAt) || !receipts[1].CollectedAt.Equal(receipts[0].CollectedAt) {
		t.Fatal("duplicate refreshed historical receipt")
	}
	pending, err = state.Pending()
	next, nextErr := state.NextSequence()
	if err != nil || nextErr != nil || pending != nil || next != 2 {
		t.Fatal("acknowledged retry did not preserve the sender sequence floor")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = lanclientstate.OpenExisting(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	pending, err = state.Pending()
	next, nextErr = state.NextSequence()
	if err != nil || nextErr != nil || pending != nil || next != 2 {
		t.Fatal("sender restart lost its acknowledged sequence floor")
	}
	assertWindowsManagerProjection(t, f, snapshots[0], receipts[0], "1")
	staleAt := receipts[0].ReceivedAt.Add(lanstore.SampleMaxAge + time.Second)
	stale := f.view(t, staleAt)
	if stale.Status != "stale" || stale.ReceivedAt == nil || stale.Snapshot == nil || !stale.ReceivedAt.Equal(receipts[0].ReceivedAt) || !stale.Snapshot.CollectedAt.Equal(reports[0].CollectedAt) {
		t.Fatal("duplicate or restart made stale inventory fresh")
	}
	expired := f.view(t, reports[0].CollectedAt.Add(24*time.Hour))
	if expired.Status != "unavailable" || expired.Snapshot != nil || expired.ReceivedAt == nil || !expired.ReceivedAt.Equal(receipts[0].ReceivedAt) {
		t.Fatal("retention expiry exposed old rows or refreshed receipt age")
	}
	// A changed payload at the same sequence must not be mistaken for a retry.
	var changed frame
	if err := json.Unmarshal(bodies[0], &changed); err != nil {
		t.Fatal(err)
	}
	changed.WindowsInventory.Hostname.Rows[0].Value = "another-invented-host"
	response := f.serve(t, f.request(t, signedhttp.WindowsPath, windowsManagerJSON(t, changed)), http.StatusConflict)
	_ = response.Body.Close()
	if got := f.view(t, time.Now().UTC()); !reflect.DeepEqual(got.Snapshot, before.Snapshot) || !got.ReceivedAt.Equal(*before.ReceivedAt) {
		t.Fatal("conflicting replay changed latest inventory")
	}
	third, err := runUsingStateWithDependencies(ctx, f.material, state, nil, nil, nil, collect, send)
	if err != nil || third.Sequence != 2 || third.RetriedPending || third.Duplicate || len(reports) != 2 {
		t.Fatal("fresh collection did not advance after restart", err)
	}
	after := f.view(t, time.Now().UTC())
	if after.Sequence == nil || *after.Sequence != 2 || !reflect.DeepEqual(after.Snapshot, &snapshots[1]) || after.Snapshot.Processes.Quality != windowsmanaged.QualityDenied || len(after.Snapshot.Processes.Rows) != 0 || !after.Snapshot.CollectedAt.After(before.Snapshot.CollectedAt) {
		t.Fatal("latest denial resurrected healthy process rows or lost capture age")
	}
	assertWindowsManagerProjection(t, f, snapshots[1], receipts[2], "2")
	// A formerly accepted exact frame is no longer a duplicate after a newer
	// generation commits. The durable manager floor rejects it after reopening.
	if err := f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.open(t)
	response = f.serve(t, f.request(t, signedhttp.WindowsPath, bodies[0]), http.StatusConflict)
	_ = response.Body.Close()
	retained := f.view(t, time.Now().UTC())
	if !reflect.DeepEqual(retained.Snapshot, after.Snapshot) || !retained.ReceivedAt.Equal(*after.ReceivedAt) {
		t.Fatal("manager restart lost its generation/replay floor")
	}
	// Reusing an existing generation ID with a fresh sequence and fresh dates
	// cannot refresh either the snapshot or the resource history.
	fresh, _, err := collectWindowsFrame(ctx, f.material.config, 3, collect)
	if err != nil {
		t.Fatal(err)
	}
	fresh.WindowsInventory.GenerationID = after.Snapshot.GenerationID
	response = f.serve(t, f.request(t, signedhttp.WindowsPath, windowsManagerJSON(t, fresh)), http.StatusConflict)
	_ = response.Body.Close()
	assertWindowsManagerProjection(t, f, snapshots[1], receipts[2], "2")
}

func assertWindowsManagerProjection(t *testing.T, f *windowsManagerFixture, snapshot windowsmanaged.Snapshot, receipt lanstore.Receipt, sequence string) {
	t.Helper()
	ctx, now := context.Background(), time.Now().UTC()
	service, err := enrollmentservice.New(f.store, f.issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := service.WindowsInventoryView(ctx, f.identity.Approval.DeviceID, now)
	if err != nil || view.Status != "fresh" || view.Snapshot == nil || !reflect.DeepEqual(*view.Snapshot, snapshot) || view.ReceivedAt == nil || !view.ReceivedAt.Equal(receipt.ReceivedAt) {
		t.Fatal("operator service projection differs from retained Windows inventory", err)
	}
	var encodedView enrollmentstore.WindowsInventoryView
	if err := json.Unmarshal(windowsManagerJSON(t, view), &encodedView); err != nil || !bytes.Equal(windowsManagerJSON(t, encodedView), windowsManagerJSON(t, view)) {
		t.Fatal("API view JSON lost typed inventory or provenance", err)
	}
	views, err := f.store.DeviceViews(ctx)
	if err != nil || len(views) != 1 || views[0].Snapshot != f.identity || views[0].Observation == nil {
		t.Fatal("store lost activated identity association", err)
	}
	d := views[0].Observation.Device
	if d.ID != f.identity.Approval.DeviceID || d.ID == "local-windows" || d.Name != d.ID || d.Platform != "windows" || d.Source != "lan" || d.Status != "unknown" || d.IP != nil || !d.LastSeen.Equal(receipt.CollectedAt) || d.CPU.Value != nil || d.CPU.Quality != "unknown" || d.Memory.Value == nil || *d.Memory.Value != 41.5 || d.Disk.Value == nil || *d.Disk.Value != 24.25 {
		t.Fatal("basic metric projection changed identity, unknown quality, or source values")
	}
	history, err := f.store.ResourceHistory(ctx, f.identity.Approval.DeviceID, now)
	if err != nil || history.Status != "available" || len(history.Points) == 0 {
		t.Fatal("accepted Windows metrics did not reach shared resource history", err)
	}
	p := history.Points[len(history.Points)-1]
	if p.Sequence != sequence || !p.ReceivedAt.Equal(receipt.ReceivedAt) || !p.CollectedAt.Equal(receipt.CollectedAt) || p.CPU.Value != nil || p.CPU.Quality != "unknown" || p.Memory.Value == nil || *p.Memory.Value != 41.5 || p.Disk.Value == nil || *p.Disk.Value != 24.25 {
		t.Fatal("resource history changed accepted Windows metric values or timestamps")
	}
	if sequence == "1" && len(history.Points) != 1 {
		t.Fatal("exact retry added another resource history point")
	}
	devices, err := service.Devices(ctx, now)
	if err != nil || len(devices) != 1 || devices[0].ID != d.ID || devices[0].Platform != "windows" || devices[0].Memory.Value == nil || *devices[0].Memory.Value != 41.5 {
		t.Fatal("dashboard projection lost accepted Windows device", err)
	}
	assertWindowsHealthProjection(t, devices[0], f.identity, now)
}

// The Health UI may require this manager-owned authority, never an agent claim.
func assertWindowsHealthProjection(t *testing.T, device model.Device, identity enrollmentstate.Snapshot, now time.Time) {
	t.Helper()
	count := 0
	for _, capability := range device.Capabilities {
		if capability.ID == "agent_identity" {
			count++
			if capability.Status != "supported" {
				t.Fatal("activated Windows inventory identity lacks supported manager authority")
			}
		}
	}
	certificate := device.AgentCertificate
	if count != 1 || certificate == nil || certificate.Source != "guided-enrollment" || certificate.ExpiresAt == nil || !certificate.ExpiresAt.Equal(time.Unix(identity.Intent.NotAfter, 0).UTC()) || !certificate.CheckedAt.Equal(now) {
		t.Fatal("Windows health metadata lost exact identity/certificate authority")
	}
}

func TestWindowsManagerPipelineRejectsOtherProfilesAndMixedScope(t *testing.T) {
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	linux := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfile, "linux")
	ctx := context.Background()
	windows, raw, err := collectWindowsFrame(ctx, f.material.config, 1, windowsSource)
	if err != nil {
		t.Fatal(err)
	}
	// A genuinely activated Linux credential still cannot submit a Windows
	// profile to its own Linux ingress, nor authenticate to the Windows store.
	for _, test := range []struct {
		name    string
		target  *windowsManagerFixture
		request *http.Request
		status  int
	}{
		{"Windows-body-on-Linux-profile", linux, linux.request(t, signedhttp.Path, raw), http.StatusForbidden},
		{"Linux-identity-on-Windows-profile", f, linux.request(t, signedhttp.WindowsPath, raw), http.StatusForbidden},
		{"Windows-path-on-Linux-ingress", linux, f.request(t, signedhttp.WindowsPath, raw), http.StatusBadRequest},
		{"Linux-path-on-Windows-ingress", f, f.request(t, signedhttp.Path, raw), http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := test.target.serve(t, test.request, test.status)
			_ = response.Body.Close()
		})
	}
	// Even a valid basic Linux frame signed by the Windows credential is
	// outside the credential's collection profile and approved platform.
	basic := windows
	basic.SchemaVersion, basic.WindowsInventory = FrameVersion, nil
	basic.Observation.Platform, basic.Observation.Observation.Platform = "linux", "linux"
	d := &basic.Observation.Observation
	d.ID, d.Name, d.Source, d.Site, d.Group = "sandbox-local", "Local sandbox", "sandbox", "Cloud sandbox", "Local observations"
	d.Tags = []string{"read-only"}
	basicRaw := windowsManagerJSON(t, basic)
	if _, err := lanstore.ValidateFrame(basicRaw, time.Now().UTC()); err != nil {
		t.Fatal("basic Linux rejection fixture is not otherwise valid", err)
	}
	response := f.serve(t, f.request(t, signedhttp.WindowsPath, basicRaw), http.StatusForbidden)
	_ = response.Body.Close()
	for _, member := range []string{"operational", "packages"} {
		t.Run("mixed-"+member, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			fields[member] = json.RawMessage(`{}`)
			response := f.serve(t, f.request(t, signedhttp.WindowsPath, windowsManagerJSON(t, fields)), http.StatusBadRequest)
			_ = response.Body.Close()
		})
	}
	if v := f.view(t, time.Now().UTC()); v.Status != "awaiting" || v.Snapshot != nil || v.ReceivedAt != nil {
		t.Fatal("rejected profiles or scope populated Windows inventory")
	}
	if v := linux.view(t, time.Now().UTC()); v.Status != "not_configured" || v.Snapshot != nil {
		t.Fatal("Linux identity acquired Windows inventory scope")
	}
	for _, fixture := range []*windowsManagerFixture{f, linux} {
		views, err := fixture.store.LatestObservations(ctx)
		if err != nil || len(views) != 0 {
			t.Fatal("rejected frame changed approved telemetry", err)
		}
		history, err := fixture.store.ResourceHistory(ctx, fixture.identity.Approval.DeviceID, time.Now().UTC())
		if err != nil || len(history.Points) != 0 {
			t.Fatal("rejected frame reached shared resource history", err)
		}
	}
	// Collection profiles remain immutable across manager restart: neither
	// database can be opened under the other profile's binding.
	for _, fixture := range []*windowsManagerFixture{f, linux} {
		if err := fixture.store.Close(); err != nil {
			t.Fatal(err)
		}
		wrong := fixture.config
		wrong.Binding.CollectionProfile = enrollmentcrypto.CollectionProfile
		if fixture == linux {
			wrong.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
		}
		store, err := enrollmentstore.Open(fixture.path, wrong, fixture.issuer.IssuerDER())
		if err == nil {
			_ = store.Close()
			t.Fatal("manager silently adopted another collection profile")
		}
		fixture.open(t)
		if _, err := fixture.store.AuthorizeCertificate(ctx, fixture.material.certificate.Certificate[0], time.Now().UTC()); err != nil {
			t.Fatal("rejected profile rebinding damaged the original identity", err)
		}
	}
}

func TestWindowsManagerPipelineOperatorHTTPBoundary(t *testing.T) {
	t.Run("event-v2", func(t *testing.T) { testWindowsManagerPipelineOperatorHTTPBoundary(t, false) })
	t.Run("events-and-volumes-v3", func(t *testing.T) { testWindowsManagerPipelineOperatorHTTPBoundary(t, true) })
}
func testWindowsManagerPipelineOperatorHTTPBoundary(t *testing.T, withVolumes bool, network ...bool) {
	withNetwork := len(network) >= 1 && network[0]
	withStartup := len(network) >= 2 && network[1]
	f := newWindowsManagerFixture(t, enrollmentcrypto.CollectionProfileWindowsInventory, "windows")
	ctx := context.Background()
	state, err := lanclientstate.InitializeNew(f.material.config.StateDirectory, f.material.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	// Supply a declared positive disk observation through the real signed sender,
	// without changing the base fixture's unknown CPU or native collection scope.
	positiveSource := func(_ context.Context, generation string) (windowsmanaged.Snapshot, model.Device, error) {
		report := syntheticWindowsReport(time.Now().UTC())
		if withStartup {
			report.Services.Quality, report.Services.Complete = "healthy", true
			report.Services.Rows = []windowsinventory.Service{{Name: "InventedA", DisplayName: "Invented service", State: "running", PID: 7}}
		}
		disk := 24.25
		report.Disk.Value, report.Disk.Quality = &disk, "healthy"
		return windowsmanaged.FromReport(report, generation)
	}
	run, err := runUsingStateWithServiceStartupDependencies(ctx, f.material, state, nil, nil, nil, positiveSource, func(r *http.Request) (*http.Response, error) {
		return f.serve(t, r, http.StatusOK), nil
	}, func() (windowseventhealth.Consent, bool) { return eventConsentFixture(f.material), true }, eventSourceFixture, func() (windowsvolumes.Consent, bool) { return volumeConsentFixture(f.material), withVolumes }, volumeSourceFixture, func() (windowsprocessmetrics.Consent, bool) { return processConsentFixture(f.material), withNetwork }, processSourceFixture, func() (windowsnetwork.Consent, bool) { return networkConsentFixture(f.material), withNetwork }, networkSourceFixture, func() (windowsmanaged.ServiceStartupConsent, bool) {
		return serviceStartupConsentFixture(f.material), withStartup
	}, serviceStartupSourceFixture)
	if err != nil || run.Sequence != 1 || run.Duplicate {
		t.Fatal("fixture sender did not commit its first Windows frame", err)
	}
	want := f.view(t, time.Now().UTC())
	if (want.ServiceStartup != nil) != withStartup || (want.Network != nil) != withNetwork || (want.ProcessMetrics != nil) != withNetwork || (want.Volumes != nil) != withVolumes || want.Events == nil || want.Snapshot == nil || want.ReceivedAt == nil || want.Sequence == nil {
		t.Fatal("accepted fixture frame is missing")
	}
	// The operator handler has one existing primary/Linux authority and a
	// separate Windows store under the same issuer, instance and origin.
	primaryConfig := f.config
	primaryConfig.Binding.CollectionProfile = enrollmentcrypto.CollectionProfile
	primaryStore, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "primary", "enrollment.sqlite"), primaryConfig, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	defer primaryStore.Close()
	primary, err := enrollmentservice.New(primaryStore, f.issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	windows, err := enrollmentservice.New(f.store, f.issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	bootstrap := func(service *enrollmentservice.Service) api.EnrollmentBootstrap {
		binding := service.Binding()
		return api.EnrollmentBootstrap{SchemaVersion: "tracebolt.enrollment-bootstrap.v2", ManagerInstanceID: binding.InstanceID, Profile: binding.Profile, EnrollmentOrigin: binding.Origin, AgentOrigin: binding.Origin, CollectionProfile: binding.CollectionProfile, IssuerRootPEM: publicPEM(f.issuer.RootDER()), IssuerPEM: publicPEM(f.issuer.IssuerDER())}
	}
	registry, err := lantrust.NewRegistry(ctx, []byte(publicPEM(f.issuer.IssuerDER())), lantrust.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	const password = "invented-windows-operator-fixture"
	salt := []byte("invented-operator-fixture-salt")
	derived := argon2.IDKey([]byte(password), salt, 2, 65536, 1, 32)
	hash := "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(derived)
	auth, err := operatorauth.New(operatorauth.Config{PasswordHash: hash})
	if err != nil {
		t.Fatal(err)
	}
	session, err := auth.Login(ctx, "127.0.0.1", password)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Logout(session.Token)
	db, err := appstore.Open(filepath.Join(t.TempDir(), "operator.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	app, err := api.New(db, 8787, t.TempDir(), model.Device{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := api.NewLANOperatorHandler(app, api.LANOperatorConfig{Origin: f.config.Binding.Origin, Auth: auth, Registry: registry, InsecureHTTPTest: true, Enrollment: primary, EnrollmentBootstrap: bootstrap(primary), WindowsEnrollment: windows, WindowsEnrollmentBootstrap: bootstrap(windows), Devices: func() ([]model.Device, error) {
		return windows.Devices(ctx, windows.Now())
	}})
	if err != nil {
		t.Fatal("operator fixture boundary rejected matching public authorities", err)
	}
	call := func(method, path string, body any, authenticated bool, origin, csrf string) *httptest.ResponseRecorder {
		t.Helper()
		var raw []byte
		if body != nil {
			raw = windowsManagerJSON(t, body)
		}
		r := httptest.NewRequest(method, f.config.Binding.Origin+path, bytes.NewReader(raw))
		r.RequestURI, r.RemoteAddr = path, "127.0.0.1:44000"
		if authenticated {
			r.AddCookie(&http.Cookie{Name: "tracebolt-http-test-session", Value: session.Token})
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("operator response lost private same-origin cache policy")
		}
		return w
	}
	path := "/api/devices/" + f.identity.Approval.DeviceID + "/windows-inventory"
	if w := call(http.MethodGet, path, nil, false, "", ""); w.Code != http.StatusUnauthorized || (bytes.Contains(w.Body.Bytes(), []byte("fixture-host")) || bytes.Contains(w.Body.Bytes(), []byte("Invented Provider"))) {
		t.Fatal("unauthenticated operator read exposed accepted Windows rows", w.Code)
	}
	w := call(http.MethodGet, path, nil, true, "", "")
	var got enrollmentstore.WindowsInventoryView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.SchemaVersion != want.SchemaVersion || got.DeviceID != want.DeviceID || got.CollectionProfile != want.CollectionProfile || got.Status != "fresh" || got.Sequence == nil || *got.Sequence != *want.Sequence || got.ReceivedAt == nil || !got.ReceivedAt.Equal(*want.ReceivedAt) || !reflect.DeepEqual(got.Snapshot, want.Snapshot) || !reflect.DeepEqual(got.Events, want.Events) || !reflect.DeepEqual(got.Volumes, want.Volumes) || !reflect.DeepEqual(got.Network, want.Network) || !reflect.DeepEqual(got.ProcessMetrics, want.ProcessMetrics) || !reflect.DeepEqual(got.ServiceStartup, want.ServiceStartup) {
		t.Fatal("authenticated HTTP view lost accepted Windows rows, identity or provenance", w.Code)
	}
	// Read the real device DTO for that same admitted Windows inventory identity.
	metadataResponse := call(http.MethodGet, "/api/devices/"+f.identity.Approval.DeviceID, nil, true, "", "")
	var metadata model.Device
	if metadataResponse.Code != http.StatusOK || json.Unmarshal(metadataResponse.Body.Bytes(), &metadata) != nil || metadata.ID != got.DeviceID || metadata.Platform != "windows" || metadata.Source != "lan" || metadata.Synthetic || metadata.Disk.Value == nil || *metadata.Disk.Value != 24.25 || metadata.Disk.Quality != "healthy" || metadata.Disk.Unit != "%" || !metadata.Disk.CollectedAt.Equal(got.Snapshot.CollectedAt) || !metadata.LastSeen.Equal(got.Snapshot.CollectedAt) || metadata.AgentCertificate == nil {
		t.Fatal("Windows device HTTP DTO lost accepted disk/identity provenance", metadataResponse.Code)
	}
	assertWindowsHealthProjection(t, metadata, f.identity, metadata.AgentCertificate.CheckedAt)
	if metadata.AgentCertificate.CheckedAt.Before(got.ServerNow) || metadata.AgentCertificate.CheckedAt.Sub(*got.ReceivedAt) > 2*time.Minute || !metadata.AgentCertificate.CheckedAt.Before(*metadata.AgentCertificate.ExpiresAt) {
		t.Fatal("positive Windows Health DTO is not fresh and authorized")
	}
	if w := call(http.MethodGet, "/api/devices/"+windowsManagerID("agent", 99)+"/windows-inventory", nil, true, "", ""); w.Code != http.StatusNotFound {
		t.Fatal("unknown Windows identity was not rejected", w.Code)
	}
	if w := call(http.MethodPost, path, nil, true, f.config.Binding.Origin, session.CSRFToken); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatal("Windows inventory route admitted a mutation", w.Code)
	}
	invitation := map[string]any{"requestId": windowsManagerID("request", 99), "platform": "windows", "collectionAcknowledged": true, "insecureHTTPAcknowledged": true}
	for _, test := range []struct{ name, origin, csrf string }{
		{"hostile-origin", "http://hostile.invalid", session.CSRFToken},
		{"missing-csrf", f.config.Binding.Origin, ""},
		{"wrong-csrf", f.config.Binding.Origin, "invented-wrong-token"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if w := call(http.MethodPost, "/api/windows/enrollment/invitations", invitation, true, test.origin, test.csrf); w.Code != http.StatusForbidden {
				t.Fatal("Windows invitation creation bypassed operator origin/CSRF", w.Code)
			}
		})
	}
	if identities, err := windows.Snapshots(ctx); err != nil || len(identities) != 1 || identities[0] != f.identity {
		t.Fatal("rejected operator mutations changed Windows enrollment state", err)
	}
	if identities, err := primary.Snapshots(ctx); err != nil || len(identities) != 0 || primary.Binding().CollectionProfile != enrollmentcrypto.CollectionProfile {
		t.Fatal("Windows operator route changed primary Linux authority", err)
	}
	w = call(http.MethodGet, "/api/devices/"+f.identity.Approval.DeviceID+"/resource-history", nil, true, "", "")
	var history enrollmentstore.ResourceHistoryView
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &history) != nil || history.DeviceID != got.DeviceID || history.Status != "available" || len(history.Points) != 1 || history.Points[0].Sequence != "1" || !history.Points[0].CollectedAt.Equal(got.Snapshot.CollectedAt) || !history.Points[0].ReceivedAt.Equal(*got.ReceivedAt) {
		t.Fatal("shared resource-history HTTP route lost the accepted Windows identity/sample", w.Code)
	}
	auth.Logout(session.Token)
	if w := call(http.MethodGet, path, nil, true, "", ""); w.Code != http.StatusUnauthorized {
		t.Fatal("revoked operator session retained Windows inventory access", w.Code)
	}
}

func TestWindowsNetworkOperatorHTTPBoundary(t *testing.T) {
	t.Run("all-scopes", func(t *testing.T) { testWindowsManagerPipelineOperatorHTTPBoundary(t, true, true) })
	t.Run("no-volumes", func(t *testing.T) { testWindowsManagerPipelineOperatorHTTPBoundary(t, false, true) })
}

func TestWindowsServiceStartupOperatorHTTPBoundary(t *testing.T) {
	t.Run("all-scopes", func(t *testing.T) { testWindowsManagerPipelineOperatorHTTPBoundary(t, true, true, true) })
	t.Run("without-network-volumes", func(t *testing.T) { testWindowsManagerPipelineOperatorHTTPBoundary(t, false, false, true) })
}
