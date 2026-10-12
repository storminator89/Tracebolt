package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmenttransport"
	"localrmm/internal/operatorauth"
	"localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatemanager"
)

// This end-to-end source fixture uses two independently enrolled TLS identities,
// the actual API and relay handlers, and independently signed synthetic executor
// reports. No socket, Windows provider, host grant or installation is involved.
func TestWindowsUpdateRegistryTwoDeviceAPIToTLSRelay(t *testing.T) {
	f := newWindowsUpdateCommitFixture(t, time.Hour)
	ctx := context.Background()
	second := windowsEventOperatorActivate(t, f.service, f.at, 2)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{127}, 32))
	executors := []ed25519.PrivateKey{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{128}, 32)), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{129}, 32))}
	snapshots := []enrollmentstate.Snapshot{f.snapshot, second}
	consent := f.consent
	consent.Binding.DeviceID = second.Approval.DeviceID
	consent.Binding.IncarnationDigest = "sha256:" + second.Issuance.CertificateHash
	consent.Binding.ExecutorID = "executor_" + strings.Repeat("5", 32)
	consent.Binding.GrantID = "grant_" + strings.Repeat("5", 32)
	consent.Binding.ExecutorKeyID = actionpermit.Digest(executors[1].Public().(ed25519.PublicKey))
	before, _ := f.saved(t)
	// An enrolled second device must still have a distinct executor pin.
	duplicate := consent
	duplicate.Binding.ExecutorKeyID = f.consent.Binding.ExecutorKeyID
	if err := f.store.store.RegisterWindowsUpdateDeviceCreateOnly(ctx, key.Public().(ed25519.PublicKey), executors[0].Public().(ed25519.PublicKey), duplicate, f.at); err == nil {
		t.Fatal("duplicate executor admitted")
	}
	if err := f.store.store.RegisterWindowsUpdateDeviceCreateOnly(ctx, key.Public().(ed25519.PublicKey), executors[1].Public().(ed25519.PublicKey), consent, f.at); err != nil {
		t.Fatal(err)
	}
	after, _ := f.saved(t)
	if !bytes.Equal(before, after) {
		t.Fatal("registration rewrote first device history")
	}
	if err := f.store.store.RegisterWindowsUpdateDeviceCreateOnly(ctx, key.Public().(ed25519.PublicKey), executors[1].Public().(ed25519.PublicKey), consent, f.at); err == nil {
		t.Fatal("registration adopted existing device")
	}
	managers := []*windowsupdatejob.Manager{}
	for _, c := range []windowsupdatejob.Consent{f.consent, consent} {
		m, err := windowsupdatejob.OpenTransactional(ctx, f.store.store, c.Binding, key, f.clock.now)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.ConfigureOperatorPolicy(func(actor string) bool { return actor == namedActorID }); err != nil {
			t.Fatal(err)
		}
		managers = append(managers, m)
		defer m.Close()
	}
	registry, err := windowsupdatejob.NewRegistry(managers)
	if err != nil {
		t.Fatal(err)
	}
	f.handler.windowsUpdateJobs = nil
	f.handler.windowsUpdateRegistry = registry
	relay, err := enrollmenttransport.New(f.store.store, f.issuer.IssuerDER(), f.store.store.Config().Binding.Origin)
	if err != nil {
		t.Fatal(err)
	}
	if err = relay.ConfigureWindowsUpdateRegistry(registry); err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(f.issuer.IssuerDER())
	call := func(index int, method, suffix string, body any) (int, []byte) {
		f.clock.set(time.Now().UTC())
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, f.handler.origin+"/api/devices/"+snapshots[index].Approval.DeviceID+"/windows-update-jobs"+suffix, bytes.NewReader(raw))
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13}
		r.RemoteAddr = "127.0.0.1:34567"
		r.AddCookie(&http.Cookie{Name: operatorauth.CookieName, Value: f.session.Token})
		r.Header.Set("Origin", f.handler.origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", f.session.CSRFToken)
		w := httptest.NewRecorder()
		f.handler.ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}
	send := func(index int, path string, body []byte) (int, []byte) {
		cert, e := f.store.store.CertificateForVerification(ctx, snapshots[index].InvitationID)
		if e != nil {
			t.Fatal(e)
		}
		leaf, _ := x509.ParseCertificate(cert.DER())
		r := httptest.NewRequest("POST", f.store.store.Config().Binding.Origin+"/v1/windows-update-jobs/"+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.RequestURI = r.URL.Path
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}
		w := httptest.NewRecorder()
		relay.ServeHTTP(w, r)
		return w.Code, w.Body.Bytes()
	}
	selection := windowsupdatejob.Selection{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 3}
	for i := 0; i < 2; i++ {
		job := fmt.Sprintf("update_%032x", i+11)
		code, raw := call(i, "POST", "/request", map[string]any{"requestId": job, "updateId": selection.UpdateID, "revision": selection.Revision})
		if code != 200 {
			t.Fatalf("request %d: %s", code, raw)
		}
		claim := []byte(`{"jobId":"` + job + `"}`)
		if code, _ = send(1-i, "readiness-claim", claim); code == 200 {
			t.Fatal("cross-device claim admitted")
		}
		code, challenge := send(i, "readiness-claim", claim)
		if code != 200 {
			t.Fatalf("claim %d: %s", code, challenge)
		}
		c, e := windowsupdatejob.VerifyChallenge(challenge, key.Public().(ed25519.PublicKey))
		if e != nil || c.Binding != managers[i].Binding() {
			t.Fatal("wrong exact signed challenge", e)
		}
		at := time.Now().UTC().Unix()
		readiness := windowsupdatejob.Readiness{Selection: selection, CapturedAt: at, Software: windowsupdatejob.Yes, Installed: windowsupdatejob.No, Hidden: windowsupdatejob.No, Downloaded: windowsupdatejob.Yes, EULAAccepted: windowsupdatejob.Yes, CanRequestUserInput: windowsupdatejob.No, CanRequireSource: windowsupdatejob.No, RequiresNetwork: windowsupdatejob.No, BundledCount: 0, InstallerBusy: windowsupdatejob.No, RebootRequiredBefore: windowsupdatejob.No, RebootBehavior: "can", OfflineVerified: windowsupdatejob.Yes}
		statement := windowsupdatejob.Statement{Version: windowsupdatejob.RelayVersion, Kind: "readiness", Binding: c.Binding, JobID: job, ReferenceDigest: actionpermit.Digest(challenge), Deadline: c.Deadline, IssuedAt: at, ExpiresAt: at + 60, Readiness: &readiness}
		report, e := windowsupdatejob.SignStatement(statement, executors[i])
		if e != nil {
			t.Fatal(e)
		}
		if code, _ = send(1-i, "report", report); code == 200 {
			t.Fatal("cross-device report admitted")
		}
		if code, raw = send(i, "report", report); code != 200 {
			t.Fatalf("report %d: %s", code, raw)
		}
		code, raw = call(i, "POST", "/preview", map[string]any{"requestId": job})
		if code != 200 {
			t.Fatalf("review %d: %s", code, raw)
		}
		var view windowsupdatejob.View
		if json.Unmarshal(raw, &view) != nil || view.Job == nil || view.Job.Preview == nil {
			t.Fatal("no reviewed preview")
		}
		code, raw = call(i, "POST", "/approve", map[string]any{"previewId": job, "previewDigest": view.Job.Preview.Digest, "acknowledged": true})
		if code != 200 {
			t.Fatalf("approval %d: %s", code, raw)
		}
		code, permit := send(i, "install-claim", claim)
		if code != 200 {
			t.Fatalf("install claim %d: %s", code, permit)
		}
		if code, _ = send(i, "install-claim", claim); code == 200 {
			t.Fatal("duplicate install delivery")
		}
		outcome := "failed"
		operation := uint32(4)
		reboot := windowsupdatejob.Unknown
		if i == 1 {
			outcome = "succeeded"
			operation = 2
			reboot = windowsupdatejob.Yes
		}
		at = time.Now().UTC().Unix()
		result := windowsupdatejob.Result{JobID: job, EnvelopeDigest: actionpermit.Digest(permit), Attempted: true, Outcome: outcome, OperationResult: operation, RebootRequired: reboot, CompletedAt: at}
		statement = windowsupdatejob.Statement{Version: windowsupdatejob.RelayVersion, Kind: "result", Binding: c.Binding, JobID: job, ReferenceDigest: actionpermit.Digest(permit), Deadline: view.Job.Preview.ExpiresAt, IssuedAt: at, ExpiresAt: at + 60, Result: &result}
		report, e = windowsupdatejob.SignStatement(statement, executors[i])
		if e != nil {
			t.Fatal(e)
		}
		if code, raw = send(i, "report", report); code != 200 {
			t.Fatalf("outcome %d: %s", code, raw)
		}
		code, raw = call(i, "GET", "?jobId="+job, nil)
		if code != 200 || json.Unmarshal(raw, &view) != nil || view.Job.Result == nil || *view.Job.Result != result {
			t.Fatalf("exact outcome %d: %s", code, raw)
		}
		code, raw = call(i, "GET", "?history=1", nil)
		var history windowsupdatejob.History
		if code != 200 || json.Unmarshal(raw, &history) != nil || len(history.Jobs) != 1 || history.RemainingCapacity != 31 || history.Jobs[0].ID != job || history.Jobs[0].Result == nil || *history.Jobs[0].Result != result {
			t.Fatalf("saved history %d: %s", code, raw)
		}
		if i == 0 && history.Available {
			t.Fatal("failed device allowed next attempt")
		}
		if i == 1 && !history.Available {
			t.Fatal("failed first device blocked second")
		}
	}
	if code, _ := call(0, "GET", "?jobId=update_"+strings.Repeat("f", 32), nil); code != 409 {
		t.Fatal("missing exact ID fell back", code)
	}
	// Explicit v2 startup preserves unavailable members rather than dropping
	// them or preventing unrelated endpoints from opening their saved state.
	root := t.TempDir()
	keyPath := filepath.Join(root, "manager.key")
	if err = os.WriteFile(keyPath, key, 0600); err != nil {
		t.Fatal(err)
	}
	files := []string{}
	for i, m := range managers {
		p := filepath.Join(root, fmt.Sprintf("device-%d.json", i))
		raw, _ := json.Marshal(windowsupdatemanager.Config{Version: windowsupdatemanager.ConfigVersion, Enabled: true, Binding: m.Binding(), PrivateKeyFile: keyPath})
		if err = os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	registryPath := filepath.Join(root, "registry.json")
	registryBytes, _ := json.Marshal(windowsupdatemanager.RegistryConfig{Version: windowsupdatemanager.RegistryVersion, Enabled: true, ManagerID: f.consent.Binding.ManagerID, ConfigFiles: files})
	if err = os.WriteFile(registryPath, registryBytes, 0600); err != nil {
		t.Fatal(err)
	}
	f.clock.set(time.Now().UTC())
	snap, err := f.store.store.Get(ctx, f.snapshot.InvitationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Terminate(ctx, snap.InvitationID, "request_"+strings.Repeat("e", 32), snap.Revision, enrollmentstate.Revoked); err != nil {
		t.Fatal(err)
	}
	reopened, err := windowsupdatemanager.LoadRegistry(ctx, f.store.store, registryPath)
	if err != nil {
		t.Fatal("revoked member disabled registry", err)
	}
	defer reopened.Close()
	if _, err = reopened.Manager(f.snapshot.Approval.DeviceID).History(ctx, f.snapshot.Approval.DeviceID); err == nil {
		t.Fatal("dormant load granted revoked authority")
	}
	if h, err := reopened.Manager(second.Approval.DeviceID).History(ctx, second.Approval.DeviceID); err != nil || len(h.Jobs) != 1 {
		t.Fatal("revoked member disabled live history", err)
	}
	if _, err = windowsupdatemanager.Load(ctx, f.store.store, files[0]); err == nil {
		t.Fatal("legacy loader silently adopted dormant registry behavior")
	}
	f.handler.auth.Logout(f.session.Token)
	if code, _ := call(0, "GET", "?history=1", nil); code != 401 {
		t.Fatal("lost session read history", code)
	}
}
