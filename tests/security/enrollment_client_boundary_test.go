//go:build linux

package security_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentclient"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanclient"
)

// Only generated ephemeral fixture credentials, a dedicated temporary state
// tree, and a loopback HTTPS listener are used. No OS trust or live account changes.
type nativeEnrollmentBoundaryFixture struct {
	bootstrap enrollmentclient.Bootstrap
	options   enrollmentclient.Options
	requests  atomic.Int64
}

func newNativeEnrollmentBoundaryFixture(t *testing.T) *nativeEnrollmentBoundaryFixture {
	t.Helper()
	materialFixture := newEnrollmentConfigFixture(t, "tls")
	material := materialFixture.load(t)
	f := &nativeEnrollmentBoundaryFixture{}
	var service *enrollmentservice.Service
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		defer r.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(r.Body, enrollmentcrypto.MaxClaimBytes+1))
		if err != nil {
			t.Error("fixture request read failed")
			return
		}
		var fields map[string]string
		if json.Unmarshal(raw, &fields) != nil {
			t.Error("fixture request parse failed")
			return
		}
		var out any
		switch strings.TrimPrefix(r.URL.Path, "/v2/enrollment/") {
		case "challenge":
			out, err = service.Challenge("127.0.0.1", fields["invitationId"], fields["claimId"], fields["purpose"])
		case "status":
			out, err = service.Status(r.Context(), fields["challenge"], raw)
		case "claim":
			var snapshot enrollmentstate.Snapshot
			snapshot, err = service.Claim(r.Context(), fields["challenge"], raw)
			out = snapshot
			if err == nil {
				_, err = service.Approve(r.Context(), snapshot.InvitationID, enrollmentBoundaryID("request_", 202), snapshot.Claim.KeyFingerprint, snapshot.Revision)
			}
		case "credential":
			out, err = service.CredentialEnvelope(r.Context(), fields["challenge"], raw)
		case "activate":
			out, err = service.Activate(r.Context(), fields["challenge"], raw)
		default:
			t.Error("unexpected enrollment route")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			if errors.Is(err, enrollmentstate.ErrState) || errors.Is(err, enrollmentstate.ErrConflict) {
				w.WriteHeader(http.StatusConflict)
				io.WriteString(w, `{"error":{"code":"enrollment_conflict","message":"Enrollment state conflicts with this request."}}`)
				return
			}
			if errors.Is(err, enrollmentstate.ErrProof) || errors.Is(err, enrollmentstate.ErrNotFound) || errors.Is(err, enrollmentcrypto.ErrProof) || errors.Is(err, enrollmentservice.ErrChallenge) {
				w.WriteHeader(http.StatusUnauthorized)
				io.WriteString(w, `{"error":{"code":"enrollment_proof_rejected","message":"Enrollment proof is invalid or expired."}}`)
				return
			}
			t.Error("unexpected fixture service failure")
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, `{"error":{"code":"enrollment_unavailable","message":"Enrollment is temporarily unavailable."}}`)
			return
		}
		json.NewEncoder(w).Encode(out)
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{materialFixture.lan.Server}}
	cfg := material.StoreConfig()
	cfg.Binding.Origin = "https://" + server.Listener.Addr().String()
	store, err := enrollmentstore.Open(filepath.Join(t.TempDir(), "manager", "store.db"), cfg, material.Issuer().IssuerDER())
	if err != nil {
		t.Fatal("fixture store creation failed")
	}
	t.Cleanup(func() { store.Close() })
	service, err = enrollmentservice.New(store, material.Issuer(), nil)
	if err != nil {
		t.Fatal("fixture service creation failed")
	}
	invitation, err := service.CreateInvitation(context.Background(), enrollmentBoundaryID("request_", 201), "linux")
	if err != nil {
		t.Fatal("fixture invitation creation failed")
	}
	f.bootstrap = enrollmentclient.Bootstrap{SchemaVersion: enrollmentclient.BootstrapVersion, ManagerInstanceID: cfg.Binding.InstanceID, Profile: "tls", EnrollmentOrigin: cfg.Binding.Origin, AgentOrigin: cfg.Binding.Origin, CollectionProfile: cfg.Binding.CollectionProfile, InvitationID: invitation.Snapshot().InvitationID, ServerCAPEM: material.ServerCAPEM(), IssuerRootPEM: material.RootPEM(), IssuerPEM: material.IssuerPEM()}
	f.options = enrollmentclient.Options{StateDirectory: filepath.Join(t.TempDir(), "client"), Timeout: 10 * time.Second, PollInterval: 2 * time.Second, Display: func(enrollmentclient.TrustDisplay) error { return nil }, Secret: func(context.Context) ([]byte, error) { return []byte(invitation.Secret()), nil }}
	server.StartTLS()
	t.Cleanup(server.Close)
	return f
}

func TestIndependentNativeEnrollmentRejectsReplacedTelemetryDirectory(t *testing.T) {
	f := newNativeEnrollmentBoundaryFixture(t)
	result, err := enrollmentclient.Run(context.Background(), f.bootstrap, f.options)
	if err != nil {
		t.Fatal("ordinary fixture enrollment failed", err)
	}
	old, err := os.Stat(result.Config.StateDirectory)
	if err != nil {
		t.Fatal("fixture telemetry directory missing")
	}
	// Preserve the original disposable directory and replace only its path.
	// A new empty directory must not silently become the prepared sender domain.
	if err = os.Rename(result.Config.StateDirectory, filepath.Join(t.TempDir(), "original-domain")); err != nil {
		t.Fatal("fixture directory preservation failed")
	}
	if err = os.Mkdir(result.Config.StateDirectory, 0700); err != nil {
		t.Fatal("fixture replacement failed")
	}
	replacement, err := os.Stat(result.Config.StateDirectory)
	if err != nil || os.SameFile(old, replacement) {
		t.Fatal("fixture did not create a distinct directory")
	}
	before := f.requests.Load()
	f.options.Secret = func(context.Context) ([]byte, error) {
		t.Error("prepared handoff requested invitation")
		return nil, enrollmentclient.ErrInput
	}
	_, err = enrollmentclient.Run(context.Background(), f.bootstrap, f.options)
	if err == nil {
		t.Fatal("replaced sender directory returned a successful ready handoff")
	}
	if !errors.Is(err, enrollmentclient.ErrState) {
		t.Fatal("replaced sender directory was not rejected before handoff")
	}
	if f.requests.Load() != before {
		t.Fatal("replaced sender directory opened network before rejection")
	}
}

func TestIndependentNativeEnrollmentTrustOrderAndPreservation(t *testing.T) {
	f := newNativeEnrollmentBoundaryFixture(t)
	options := f.options
	options.Display = func(d enrollmentclient.TrustDisplay) error {
		if f.requests.Load() != 0 || d.EnrollmentOrigin != f.bootstrap.EnrollmentOrigin || d.AgentOrigin != f.bootstrap.AgentOrigin || d.HTTPTest || len(d.KeyFingerprint) != 64 || len(d.ComparisonCode) != 32 || len(d.ServerCAFingerprints) != 1 || len(d.IssuerFingerprint) != 64 || len(d.IssuerRootFingerprint) != 64 {
			t.Error("public trust display contract violated")
		}
		return errors.New("synthetic display interruption")
	}
	options.Secret = func(context.Context) ([]byte, error) {
		t.Error("secret requested after interrupted display")
		return nil, enrollmentclient.ErrInput
	}
	if _, err := enrollmentclient.Run(context.Background(), f.bootstrap, options); !errors.Is(err, enrollmentclient.ErrInput) || f.requests.Load() != 0 {
		t.Fatal("display interruption opened network")
	}
	ledgerPath := filepath.Join(options.StateDirectory, "ledger.json")
	before, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal("local operation was not durable before display")
	}
	defer clear(before)
	var prior map[string]json.RawMessage
	if json.Unmarshal(before, &prior) != nil {
		t.Fatal("fixture ledger was invalid")
	}
	options = f.options
	getSecret := options.Secret
	var returned []byte
	var secretCopy []byte
	options.Secret = func(ctx context.Context) ([]byte, error) {
		var err error
		returned, err = getSecret(ctx)
		secretCopy = bytes.Clone(returned)
		return returned, err
	}
	defer func() { clear(returned); clear(secretCopy) }()
	result, err := enrollmentclient.Run(context.Background(), f.bootstrap, options)
	if err != nil || !result.ServerAuthenticated {
		t.Fatal("ordinary authenticated handoff failed", err)
	}
	if len(returned) != 43 || !bytes.Equal(returned, make([]byte, len(returned))) {
		t.Fatal("client did not clear callback invitation buffer")
	}
	if _, err := lanclient.Load(result.ConfigPath); err != nil {
		t.Fatal("native sender rejected protected handoff")
	}
	after, err := os.ReadFile(ledgerPath)
	defer clear(after)
	var current map[string]json.RawMessage
	if err != nil || json.Unmarshal(after, &current) != nil {
		t.Fatal("fixture ledger disappeared")
	}
	for _, field := range []string{"bootstrap", "seed", "csr", "claimId", "claimRequestId", "statusRequestId", "credentialRequestId", "activationRequestId"} {
		if !bytes.Equal(prior[field], current[field]) {
			t.Fatal("resume changed immutable local operation field", field)
		}
	}
	artifacts := make(map[string][]byte)
	for _, name := range []string{"ledger.json", "agent-key.pem", "agent-cert.pem", "server-ca.pem", "agent.json", "ready.json"} {
		raw, err := os.ReadFile(filepath.Join(options.StateDirectory, name))
		if err != nil || bytes.Contains(raw, secretCopy) || bytes.Contains(raw, []byte(`"invitationSecret"`)) {
			t.Fatal("missing artifact or invitation-bearing artifact", name)
		}
		artifacts[name] = raw
	}
	defer func() {
		for _, raw := range artifacts {
			clear(raw)
		}
	}()
	sentinelPath := filepath.Join(result.Config.StateDirectory, "sender-sentinel")
	sentinel := []byte("synthetic independent sender state")
	if os.WriteFile(sentinelPath, sentinel, 0600) != nil {
		t.Fatal("could not create disposable sender sentinel")
	}
	options.Secret = func(context.Context) ([]byte, error) {
		t.Error("ready handoff requested invitation")
		return nil, enrollmentclient.ErrInput
	}
	if _, err := enrollmentclient.Run(context.Background(), f.bootstrap, options); err != nil {
		t.Fatal("ready handoff resume failed", err)
	}
	for name, want := range artifacts {
		got, err := os.ReadFile(filepath.Join(options.StateDirectory, name))
		equal := bytes.Equal(got, want)
		clear(got)
		if err != nil || !equal {
			t.Fatal("ready resume mutated protected artifact", name)
		}
	}
	got, err := os.ReadFile(sentinelPath)
	if err != nil || !bytes.Equal(got, sentinel) {
		t.Fatal("enrollment disturbed independent sender state")
	}
}

func TestIndependentNativeEnrollmentPreservesSenderCrashTemporary(t *testing.T) {
	f := newNativeEnrollmentBoundaryFixture(t)
	result, err := enrollmentclient.Run(context.Background(), f.bootstrap, f.options)
	if err != nil {
		t.Fatal("ordinary fixture enrollment failed", err)
	}
	path := filepath.Join(result.Config.StateDirectory, ".state.tmp")
	want := []byte("synthetic uncommitted sender work; never an enrollment cleanup target")
	if os.WriteFile(path, want, 0600) != nil {
		t.Fatal("disposable sender temporary creation failed")
	}
	f.options.Secret = func(context.Context) ([]byte, error) {
		t.Error("ready handoff requested invitation")
		return nil, enrollmentclient.ErrInput
	}
	_, err = enrollmentclient.Run(context.Background(), f.bootstrap, f.options)
	// A validator may conservatively stop or keep the valid committed ledger;
	// neither outcome grants enrollment ownership of sender crash recovery.
	if err != nil && !errors.Is(err, enrollmentclient.ErrState) {
		t.Fatal("unexpected resume outcome")
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, want) {
		t.Fatal("enrollment validation removed or changed sender crash temporary")
	}
}
