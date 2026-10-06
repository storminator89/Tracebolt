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
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Issue a real synthetic identity through the service's proof checks. It is not
// activated, so metadata remains unknown until the identity expires. No native
// collection, listener, endpoint provisioning or external service is involved.
func systemInventoryIssuedClockFixture(t *testing.T, service *enrollmentservice.Service, now time.Time) enrollmentstate.Snapshot {
	t.Helper()
	return inventoryIdentityClockFixture(t, service, now, false)
}

// Optional activation remains an in-memory proof over a synthetic identity.
func inventoryIdentityClockFixture(t *testing.T, service *enrollmentservice.Service, now time.Time, activate bool) enrollmentstate.Snapshot {
	t.Helper()
	ctx := context.Background()
	requestID := func(n string) string { return "request_" + strings.Repeat(n, 32) }
	created, err := service.CreateInvitation(ctx, requestID("1"), "linux")
	if err != nil {
		t.Fatal("fixture invitation failed", err)
	}
	invitation := created.Snapshot().InvitationID
	claimID := "claim_" + strings.Repeat("2", 32)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Synthetic system clock fixture"}}, key)
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
	raw, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": challenge.Context.ManagerInstanceID, "profile": challenge.Context.Profile, "origin": challenge.Context.Origin, "collectionProfile": challenge.Context.CollectionProfile, "invitationId": invitation, "claimId": claimID, "requestId": requestID("2"), "challenge": challenge.Context.Challenge, "invitationSecret": created.Secret(), "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, message))})
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
	if !activate {
		return issued
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

func TestSystemInventoryMetadataFinalOutputRechecksIdentityAndSession(t *testing.T) {
	for _, crossing := range []string{"success", "final_clock_expiry", "session_check_expiry", "session_revoked", "after_commit_cancel"} {
		t.Run(crossing, func(t *testing.T) {
			start := time.Now().UTC().Truncate(time.Second)
			checked := start
			calls := 0
			var onClock func(int)
			now := func() time.Time {
				calls++
				if onClock != nil {
					onClock(calls)
				}
				return checked
			}
			service := overviewServiceFixtureWithClock(t, "https://overview.invalid", now)
			issued := systemInventoryIssuedClockFixture(t, service, start)
			expiry := time.Unix(issued.Intent.NotAfter, 0).UTC()
			calls = 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			onClock = func(call int) {
				// Initial API timestamp, post-load refresh, post-commit refresh,
				// then the final output timestamp supplied by the trusted service.
				if crossing == "final_clock_expiry" && call >= 4 {
					checked = expiry
				}
				if crossing == "after_commit_cancel" && call == 3 {
					cancel()
				}
			}
			activeChecks := 0
			r := httptest.NewRequest("GET", "/api/devices/"+issued.Approval.DeviceID+"/inventory/system", nil)
			r = r.WithContext(context.WithValue(ctx, operatorRequestKey{}, operatorRequest{active: func() bool {
				activeChecks++
				if crossing == "session_check_expiry" {
					checked = expiry
				}
				return crossing != "session_revoked"
			}}))
			h := operatorHandler{app: setup(t), enrollment: service}
			w := httptest.NewRecorder()
			h.systemInventory(w, r)
			if crossing == "session_revoked" || crossing == "after_commit_cancel" {
				if w.Code != 401 || strings.Contains(w.Body.String(), "tracebolt.system-inventory-view") || strings.Contains(w.Body.String(), issued.Approval.DeviceID) {
					t.Fatal("revoked or canceled request exposed metadata", w.Code)
				}
				return
			}
			var view enrollmentstore.SystemView
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || activeChecks != 1 {
				t.Fatal("authorized metadata response missing", w.Code)
			}
			want := "unknown"
			if crossing != "success" {
				want = "expired"
			}
			if view.Status != want || !view.ServerNow.Equal(checked) || view.DeviceID != issued.Approval.DeviceID || view.SchemaVersion != "tracebolt.system-inventory-view.v1" {
				t.Fatalf("final output used old identity time: status=%q want=%q clockCalls=%d", view.Status, want, calls)
			}
			if view.Latest != nil || view.LastComplete.Services != nil || view.LastComplete.Sockets != nil || view.ReceivedAt != nil || view.Sequence != nil {
				t.Fatal("unactivated identity manufactured observations")
			}
			if strings.Contains(w.Body.String(), "readState") || strings.Contains(w.Body.String(), "certificateNotAfter") {
				t.Fatal("private read-time authority escaped the DTO")
			}
		})
	}
}

func TestSystemInventoryMetadataFairReadPreservesOperatorGuards(t *testing.T) {
	o := newOperatorFixture(t, time.Minute)
	h := o.server.Config.Handler.(*operatorHandler)
	at := time.Now().UTC().Truncate(time.Second)
	var clockCalls atomic.Int64
	h.enrollment = overviewServiceFixtureWithClock(t, o.server.URL, func() time.Time {
		clockCalls.Add(1)
		return at
	})
	issued := systemInventoryIssuedClockFixture(t, h.enrollment, at)
	path := "/api/devices/" + issued.Approval.DeviceID + "/inventory/system"
	clockCalls.Store(0)
	if response, _ := o.call(t, "GET", path, nil, "", nil); response.StatusCode != 401 || clockCalls.Load() != 0 {
		t.Fatal("anonymous request reached system inventory admission")
	}
	o.login(t)
	for _, tc := range []struct {
		name, method, path string
		change             func(*http.Request)
		want               int
	}{
		{"query string", "GET", path + "?search=private", nil, 400},
		{"cross origin", "GET", path, func(r *http.Request) { r.Header.Set("Origin", "https://other.invalid") }, 403},
		{"cross site", "GET", path, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"wrong host", "GET", path, func(r *http.Request) { r.Host = "other.invalid" }, 403},
		{"wrong method", "POST", path, nil, 405},
		{"query without CSRF", "POST", path + "/query", nil, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clockCalls.Store(0)
			response, value := o.call(t, tc.method, tc.path, nil, "", tc.change)
			if response.StatusCode != tc.want || clockCalls.Load() != 0 || value["schemaVersion"] != nil || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("request guard changed or reached inventory admission: status=%d calls=%d", response.StatusCode, clockCalls.Load())
			}
		})
	}
	clockCalls.Store(0)
	response, value := o.call(t, "GET", path, nil, "", nil)
	if response.StatusCode != 200 || value["status"] != "unknown" || value["deviceId"] != issued.Approval.DeviceID || value["latest"] != nil || clockCalls.Load() < 4 || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("authorized metadata read or trusted clock checks lost", response.StatusCode)
	}
}
