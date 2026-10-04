//go:build linux

package enrollmentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanclient"
	"localrmm/internal/lanclientstate"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testID(p string, n int) string { return fmt.Sprintf("%s_%032x", p, n) }
func testPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

type clientFixture struct {
	t                                               *testing.T
	server                                          *httptest.Server
	service                                         *enrollmentservice.Service
	bootstrap                                       Bootstrap
	secret                                          string
	state                                           string
	mu                                              sync.Mutex
	autoApprove                                     bool
	dropClaimBefore, dropClaimAfter, dropActivation bool
	unknownClaimError                               bool
	malformedClaimError                             bool
	corruptCredential                               bool
	requests                                        []string
	claims                                          []map[string]string
}

func newClientFixture(t *testing.T, profile string, collection ...string) *clientFixture {
	t.Helper()
	now := time.Now().UTC()
	rp, rk, _ := ed25519.GenerateKey(rand.Reader)
	ip, ik, _ := ed25519.GenerateKey(rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("rootfixture")}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(rd)
	issuerT := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("issuerfixture")}
	id, e := x509.CreateCertificate(rand.Reader, issuerT, root, ip, rk)
	if e != nil {
		t.Fatal(e)
	}
	issuer, e := enrollmentissuer.New(id, rd, ik, fingerprint(id), now)
	if e != nil {
		t.Fatal(e)
	}
	f := &clientFixture{t: t, state: filepath.Join(t.TempDir(), "client"), autoApprove: true}
	f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	origin := "http://" + f.server.Listener.Addr().String()
	serverCA := ""
	if profile == "tls" {
		origin = "https://" + f.server.Listener.Addr().String()
		sp, sk, _ := ed25519.GenerateKey(rand.Reader)
		serverT := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Disposable loopback server"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		sd, e := x509.CreateCertificate(rand.Reader, serverT, root, sp, rk)
		if e != nil {
			t.Fatal(e)
		}
		f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{sd}, PrivateKey: sk}}}
		serverCA = testPEM(rd)
	}
	binding := enrollmentstate.Binding{InstanceID: testID("manager", 1), Profile: profile, Origin: origin, CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerFingerprint: fingerprint(id)}
	if len(collection) == 1 {
		binding.CollectionProfile = collection[0]
	}
	cfg := enrollmentstate.DefaultConfig(binding)
	cfg.RecordLimit = 25
	cfg.InvitationLimit = 25
	cfg.PendingLimit = 25
	store, e := enrollmentstore.Open(filepath.Join(t.TempDir(), "private", "store.db"), cfg, id)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	f.service, e = enrollmentservice.New(store, issuer, nil)
	if e != nil {
		t.Fatal(e)
	}
	invitation, e := f.service.CreateInvitation(context.Background(), testID("request", 1), "linux")
	if e != nil {
		t.Fatal(e)
	}
	f.secret = invitation.Secret()
	f.bootstrap = Bootstrap{SchemaVersion: BootstrapVersion, ManagerInstanceID: binding.InstanceID, Profile: profile, EnrollmentOrigin: origin, AgentOrigin: origin, CollectionProfile: binding.CollectionProfile, InvitationID: invitation.Snapshot().InvitationID, ServerCAPEM: serverCA, IssuerRootPEM: testPEM(rd), IssuerPEM: testPEM(id)}
	if profile == "tls" {
		f.server.StartTLS()
	} else {
		f.server.Start()
	}
	t.Cleanup(f.server.Close)
	return f
}
func (f *clientFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v2/enrollment/")
	f.requests = append(f.requests, path)
	if _, e := os.Stat(filepath.Join(f.state, "ledger.json")); e != nil {
		f.t.Error("request preceded durable client ledger")
	}
	raw, _ := io.ReadAll(io.LimitReader(r.Body, enrollmentcrypto.MaxClaimBytes+1))
	var out any
	var e error
	if path == "challenge" {
		var in struct{ InvitationID, ClaimID, Purpose string }
		json.Unmarshal(raw, &in)
		out, e = f.service.Challenge("127.0.0.1", in.InvitationID, in.ClaimID, in.Purpose)
	} else {
		var fields map[string]string
		json.Unmarshal(raw, &fields)
		nonce := fields["challenge"]
		switch path {
		case "claim":
			// Keep only public identity fields in fixture records, never invitations.
			f.claims = append(f.claims, map[string]string{"claimId": fields["claimId"], "requestId": fields["requestId"], "csr": fields["csr"]})
			if f.dropClaimBefore {
				f.dropClaimBefore = false
				dropConnection(w)
				return
			}
			var v enrollmentstate.Snapshot
			v, e = f.service.Claim(r.Context(), nonce, raw)
			out = v
			if e == nil && f.autoApprove {
				_, e = f.service.Approve(r.Context(), v.InvitationID, testID("request", 100), v.Claim.KeyFingerprint, v.Revision)
			}
			if f.dropClaimAfter {
				f.dropClaimAfter = false
				dropConnection(w)
				return
			}
		case "status":
			out, e = f.service.Status(r.Context(), nonce, raw)
		case "credential":
			var v enrollmentservice.CredentialEnvelope
			v, e = f.service.CredentialEnvelope(r.Context(), nonce, raw)
			if f.corruptCredential {
				v.Intent.CollectionProfile = "unexpected"
			}
			out = v
		case "activate":
			out, e = f.service.Activate(r.Context(), nonce, raw)
			if f.dropActivation {
				f.dropActivation = false
				dropConnection(w)
				return
			}
		default:
			e = errors.New("bad route")
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if e != nil {
		status := 503
		switch {
		case errors.Is(e, enrollmentstate.ErrState), errors.Is(e, enrollmentstate.ErrConflict):
			status = 409
		case errors.Is(e, enrollmentstate.ErrNotFound), errors.Is(e, enrollmentstate.ErrProof), errors.Is(e, enrollmentstate.ErrExpired), errors.Is(e, enrollmentcrypto.ErrProof), errors.Is(e, enrollmentservice.ErrChallenge):
			status = 401
		case errors.Is(e, enrollmentservice.ErrBusy):
			status = 429
		}
		w.WriteHeader(status)
		code, message := "enrollment_unavailable", "Enrollment is temporarily unavailable."
		if status == 401 {
			code, message = "enrollment_proof_rejected", "Enrollment proof is invalid or expired."
		}
		if status == 400 {
			code, message = "invalid_enrollment_request", "Enrollment request is invalid or unsupported."
		}
		if f.unknownClaimError && path == "claim" {
			code, message = "login_required", "Intermediary fixture requires authentication."
		}
		if f.malformedClaimError && path == "claim" {
			io.WriteString(w, `{"error":{"code":"enrollment_proof_rejected","message":`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
		return
	}
	json.NewEncoder(w).Encode(out)
}
func dropConnection(w http.ResponseWriter) {
	c, _, e := w.(http.Hijacker).Hijack()
	if e == nil {
		c.Close()
	}
}
func (f *clientFixture) options() Options {
	return Options{StateDirectory: f.state, InsecureHTTPAcknowledged: f.bootstrap.Profile == "http-test", PollInterval: 2 * time.Second, Timeout: 30 * time.Second, Display: func(d TrustDisplay) error {
		if d.EnrollmentOrigin != f.bootstrap.EnrollmentOrigin || len(d.KeyFingerprint) != 64 || len(d.ComparisonCode) != 32 {
			f.t.Error("invalid local trust display")
		}
		return nil
	}, Secret: func(context.Context) ([]byte, error) { return []byte(f.secret), nil }}
}
func TestGuidedEnrollmentHTTPAndTLS(t *testing.T) {
	for _, profile := range []string{"http-test", "tls"} {
		t.Run(profile, func(t *testing.T) {
			f := newClientFixture(t, profile)
			o := f.options()
			prompts := 0
			displayed := false
			display := o.Display
			o.Display = func(d TrustDisplay) error { displayed = true; return display(d) }
			o.Secret = func(context.Context) ([]byte, error) {
				if !displayed {
					t.Error("secret before display")
				}
				prompts++
				return []byte(f.secret), nil
			}
			result, e := Run(context.Background(), f.bootstrap, o)
			if e != nil {
				t.Fatal(e)
			}
			if result.Config.SchemaVersion != lanclient.GuidedConfigVersion {
				t.Fatal("handoff lacks guided existing-state schema")
			}
			if prompts != 1 || result.ServerAuthenticated != (profile == "tls") {
				t.Fatal("wrong prompt/auth result")
			}
			if _, e := lanclient.Load(result.ConfigPath); e != nil {
				t.Fatal("sender rejected handoff", e)
			}
			for _, name := range []string{"ledger.json", "agent-key.pem", "agent-cert.pem", "agent.json", "ready.json"} {
				info, e := os.Lstat(filepath.Join(f.state, name))
				if e != nil || info.Mode().Perm() != 0600 {
					t.Fatal("unprotected output", name)
				}
			}
			for _, name := range []string{"ledger.json", "agent.json", "ready.json"} {
				raw, _ := os.ReadFile(filepath.Join(f.state, name))
				if bytes.Contains(raw, []byte(f.secret)) {
					t.Fatal("secret persisted")
				}
			}
			if result.Config.StateDirectory != filepath.Join(f.state, "telemetry") {
				t.Fatal("sender sequence state is not separated")
			}
		})
	}
}
func TestUncertainClaimsAndActivationReconcile(t *testing.T) {
	for _, mode := range []string{"claim_after", "claim_before", "activation"} {
		t.Run(mode, func(t *testing.T) {
			f := newClientFixture(t, "http-test")
			f.dropClaimAfter = mode == "claim_after"
			f.dropClaimBefore = mode == "claim_before"
			f.dropActivation = mode == "activation"
			o := f.options()
			prompts := 0
			o.Secret = func(context.Context) ([]byte, error) { prompts++; return []byte(f.secret), nil }
			_, e := Run(context.Background(), f.bootstrap, o)
			if e != nil {
				t.Fatal(e)
			}
			want := 1
			if mode == "claim_before" {
				want = 2
			}
			if prompts != want {
				t.Fatal("wrong secret re-entry count", prompts)
			}
			for _, c := range f.claims {
				if c["claimId"] != f.claims[0]["claimId"] || c["requestId"] != f.claims[0]["requestId"] || c["csr"] != f.claims[0]["csr"] {
					t.Fatal("uncertain claim changed identity")
				}
			}
		})
	}
}
func TestPendingResumePreservesIdentityAndSenderState(t *testing.T) {
	f := newClientFixture(t, "http-test")
	f.autoApprove = false
	o := f.options()
	o.Notify = func(p Progress) error {
		if p.Phase == "pending_approval" {
			return errors.New("fixture interruption")
		}
		return nil
	}
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var prior ledger
	if strictJSON(raw, &prior) != nil {
		t.Fatal("ledger")
	}
	views, e := f.service.Snapshots(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	v := views[0]
	if _, e = f.service.Approve(context.Background(), v.InvitationID, testID("request", 101), v.Claim.KeyFingerprint, v.Revision); e != nil {
		t.Fatal(e)
	}
	o = f.options()
	o.Secret = func(context.Context) ([]byte, error) {
		t.Error("secret requested for committed claim")
		return nil, ErrInput
	}
	result, e := Run(context.Background(), f.bootstrap, o)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var after ledger
	strictJSON(raw, &after)
	if prior.Seed != after.Seed || prior.ClaimID != after.ClaimID || prior.ClaimRequestID != after.ClaimRequestID {
		t.Fatal("restart changed identity")
	}
	sender := filepath.Join(result.Config.StateDirectory, "state.json")
	senderState, e := lanclientstate.OpenExisting(result.Config.StateDirectory, senderFixtureBinding(t, result.Config))
	if e != nil {
		t.Fatal(e)
	}
	pending, e := senderState.Stage(1, []byte(`{"synthetic":"first"}`))
	if e != nil {
		t.Fatal(e)
	}
	if e = senderState.Acknowledge(pending.Digest); e != nil {
		t.Fatal(e)
	}
	if _, e = senderState.Stage(2, []byte(`{"synthetic":"retained-pending"}`)); e != nil {
		t.Fatal(e)
	}
	if e = senderState.Close(); e != nil {
		t.Fatal(e)
	}
	expected, e := os.ReadFile(sender)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Run(context.Background(), f.bootstrap, o); e != nil {
		t.Fatal(e)
	}
	kept, _ := os.ReadFile(sender)
	if !bytes.Equal(kept, expected) {
		t.Fatal("sender sequence floor or exact pending bytes changed")
	}
}
func TestDeliveredIntentMismatchNeverActivates(t *testing.T) {
	f := newClientFixture(t, "http-test")
	f.corruptCredential = true
	if _, e := Run(context.Background(), f.bootstrap, f.options()); !errors.Is(e, ErrResponse) {
		t.Fatal(e)
	}
	for _, p := range f.requests {
		if p == "activate" {
			t.Fatal("bad intent activated")
		}
	}
	if _, e := os.Stat(filepath.Join(f.state, "ready.json")); !os.IsNotExist(e) {
		t.Fatal("bad intent became ready")
	}
}
func TestBootstrapAndStateMismatchFailBeforeSecret(t *testing.T) {
	f := newClientFixture(t, "http-test")
	o := f.options()
	o.Display = func(TrustDisplay) error { return errors.New("stop before network") }
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
	f.bootstrap.InvitationID = testID("invite", 99)
	o.Display = func(TrustDisplay) error { t.Error("displayed mismatched state"); return nil }
	o.Secret = func(context.Context) ([]byte, error) { t.Error("prompted mismatched state"); return nil, nil }
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	if len(f.requests) != 0 {
		t.Fatal("mismatch opened network")
	}
}

func TestPreparedHandoffNeverRecreatesMissingSenderDomain(t *testing.T) {
	f := newClientFixture(t, "http-test")
	o := f.options()
	if _, e := Run(context.Background(), f.bootstrap, o); e != nil {
		t.Fatal(e)
	}
	// Preserve the complete disposable sender domain elsewhere. The durable
	// initialization checkpoint must prevent inventing a new domain.
	if e := os.Rename(filepath.Join(f.state, "telemetry"), filepath.Join(t.TempDir(), "preserved-telemetry")); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(f.state, "ready.json")); e != nil {
		t.Fatal(e)
	}
	before := len(f.requests)
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	if len(f.requests) != before {
		t.Fatal("corrupt handoff opened network")
	}
	if _, e := os.Stat(filepath.Join(f.state, "telemetry")); !os.IsNotExist(e) {
		t.Fatal("missing sender domain recreated")
	}
}
func TestForeignArtifactBeforeActivationRejectedWithoutMutation(t *testing.T) {
	f := newClientFixture(t, "http-test")
	o := f.options()
	o.Display = func(TrustDisplay) error { return ErrInput }
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
	p := filepath.Join(f.state, "agent-key.pem")
	sentinel := []byte("unrelated fixture file")
	if e := os.WriteFile(p, sentinel, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Run(context.Background(), f.bootstrap, f.options()); !errors.Is(e, ErrState) {
		t.Fatal(e)
	}
	kept, _ := os.ReadFile(p)
	if !bytes.Equal(kept, sentinel) || len(f.requests) != 0 {
		t.Fatal("foreign artifact used or mutated")
	}
}
func TestPendingCancellationAndBoundedTimeout(t *testing.T) {
	f := newClientFixture(t, "http-test")
	f.autoApprove = false
	o := f.options()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.Notify = func(p Progress) error {
		if p.Phase == "pending_approval" {
			cancel()
		}
		return nil
	}
	start := time.Now()
	if _, e := Run(ctx, f.bootstrap, o); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel did not interrupt wait")
	}
	before := len(f.requests)
	o = f.options()
	o.Timeout = time.Second
	o.Secret = func(context.Context) ([]byte, error) { t.Error("prompted pending claim"); return nil, ErrInput }
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	if len(f.requests)-before > 2 {
		t.Fatal("pending busy loop")
	}
}
func TestWrongValidSecretDoesNotRebindSavedClaim(t *testing.T) {
	f := newClientFixture(t, "http-test")
	o := f.options()
	wrong := bytes.Repeat([]byte{3}, 32)
	fake := base64.RawURLEncoding.EncodeToString(wrong)
	o.Secret = func(context.Context) ([]byte, error) { return []byte(fake), nil }
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var before ledger
	strictJSON(raw, &before)
	if _, e := Run(context.Background(), f.bootstrap, f.options()); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var after ledger
	strictJSON(raw, &after)
	if before.ClaimHash != after.ClaimHash || before.Seed != after.Seed || before.ClaimID != after.ClaimID {
		t.Fatal("rejected claim silently rebound")
	}
	if len(f.claims) != 1 {
		t.Fatal("different semantic claim transmitted")
	}
}
func TestBootstrapStrictFramingAndAcknowledgement(t *testing.T) {
	f := newClientFixture(t, "http-test")
	raw, _ := json.Marshal(f.bootstrap)
	for _, bad := range [][]byte{append(append([]byte{}, raw...), []byte(` {}`)...), bytes.Replace(raw, []byte(`"profile":"http-test"`), []byte(`"profile":"http-test","profile":"http-test"`), 1), bytes.Replace(raw, []byte(`"profile":"http-test"`), []byte(`"Profile":"http-test"`), 1), bytes.Replace(raw, []byte(`"profile":"http-test"`), []byte(`"profile":null`), 1)} {
		var b Bootstrap
		if strictJSON(bad, &b) == nil {
			t.Fatal("ambiguous bootstrap accepted")
		}
	}
	bad := f.bootstrap
	bad.IssuerPEM = "-----BEGIN CERTIFICATE-----\nmalformed first block\n" + bad.IssuerPEM
	if _, e := validateBootstrap(bad, time.Now()); !errors.Is(e, ErrBootstrap) {
		t.Fatal("malformed PEM prefix skipped")
	}
	o := f.options()
	o.InsecureHTTPAcknowledged = false
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrBootstrap) {
		t.Fatal("HTTP without explicit acknowledgement")
	}
	if len(f.requests) != 0 {
		t.Fatal("invalid bootstrap opened network")
	}
}
func TestBootstrapLoadRejectsSecretBearingUnknownFields(t *testing.T) {
	f := newClientFixture(t, "http-test")
	raw, _ := json.Marshal(f.bootstrap)
	raw = append(raw[:len(raw)-1], []byte(`,"invitationSecret":"synthetic-nonsecret"}`)...)
	p := filepath.Join(t.TempDir(), "bootstrap.json")
	if e := os.WriteFile(p, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadBootstrap(p); !errors.Is(e, ErrBootstrap) {
		t.Fatal("secret-bearing bootstrap accepted")
	}
}
func TestWireRejectsOversizeEncodedAndAmbiguousResponses(t *testing.T) {
	for _, kind := range []string{"encoded", "oversize", "duplicate", "redirect"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch kind {
				case "encoded":
					w.Header().Set("Content-Encoding", "gzip")
					io.WriteString(w, `{}`)
				case "oversize":
					io.WriteString(w, strings.Repeat("x", maxJSON+1))
				case "duplicate":
					w.Header().Add("Content-Type", "application/json")
					io.WriteString(w, `{}`)
				case "redirect":
					w.Header().Set("Location", "http://127.0.0.1:1")
					w.WriteHeader(302)
					io.WriteString(w, `{}`)
				}
			}))
			defer srv.Close()
			c, e := lanclient.NewBootstrapHTTPClient(srv.URL, "http-test", nil)
			if e != nil {
				t.Fatal(e)
			}
			defer c.CloseIdleConnections()
			w := wireClient{client: c, origin: srv.URL}
			if _, e = w.post(context.Background(), "challenge", []byte(`{}`)); e == nil {
				t.Fatal("bad response accepted")
			}
		})
	}
}

func TestTLSDefiniteWrongSecretCorrectionRetainsKeyAndOperation(t *testing.T) {
	f := newClientFixture(t, "tls")
	o := f.options()
	o.Secret = func(context.Context) ([]byte, error) {
		return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))), nil
	}
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var before ledger
	if strictJSON(raw, &before) != nil || !before.ClaimDefinitelyRejected || before.ClaimConfirmed {
		t.Fatal("authenticated rejection marker missing")
	}
	if _, e := Run(context.Background(), f.bootstrap, f.options()); e != nil {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var after ledger
	strictJSON(raw, &after)
	if before.Seed != after.Seed || before.CSR != after.CSR || before.ClaimID != after.ClaimID || before.ClaimRequestID != after.ClaimRequestID || before.ClaimHash == after.ClaimHash || after.ClaimDefinitelyRejected || !after.Activated {
		t.Fatal("TLS correction did not retain identity and clear rejection")
	}
	if len(f.claims) != 2 {
		t.Fatal("incorrect claim count")
	}
	for k, v := range f.claims[0] {
		if f.claims[1][k] != v {
			t.Fatal("TLS correction changed operation")
		}
	}
}

func TestTLSUnknownRejectionCannotEnableSecretCorrection(t *testing.T) {
	f := newClientFixture(t, "tls")
	f.unknownClaimError = true
	o := f.options()
	o.Secret = func(context.Context) ([]byte, error) {
		return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))), nil
	}
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var before ledger
	strictJSON(raw, &before)
	if before.ClaimDefinitelyRejected {
		t.Fatal("unknown response authorized correction")
	}
	if _, e := Run(context.Background(), f.bootstrap, f.options()); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var after ledger
	strictJSON(raw, &after)
	if before.ClaimHash != after.ClaimHash || len(f.claims) != 1 {
		t.Fatal("unknown response changed semantic claim")
	}
}

func TestAmbiguousClaimCandidateSurvivesDefiniteRejectionAndRestart(t *testing.T) {
	f := newClientFixture(t, "tls")
	f.dropClaimBefore = true
	o := f.options()
	fake := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	o.Secret = func(context.Context) ([]byte, error) { return []byte(fake), nil }
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var before ledger
	strictJSON(raw, &before)
	if before.ClaimHash == "" || before.AmbiguousClaimHash != before.ClaimHash || before.ClaimDefinitelyRejected {
		t.Fatal("earlier ambiguous candidate discarded after definite rejection")
	}
	if _, e := Run(context.Background(), f.bootstrap, f.options()); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var after ledger
	strictJSON(raw, &after)
	if before.AmbiguousClaimHash != after.AmbiguousClaimHash || before.ClaimHash != after.ClaimHash || before.Seed != after.Seed || before.ClaimID != after.ClaimID || len(f.claims) != 2 {
		t.Fatal("restart changed ambiguous candidate or transmitted correction")
	}
}
func TestPrivateHandlesRedactFormattingAndGenericJSON(t *testing.T) {
	const private = "SYNTHETIC_PRIVATE_SENTINEL"
	l := ledger{&ledgerData{Seed: private, CSR: private}}
	s := session{&sessionData{l: l, key: ed25519.PrivateKey(private)}}
	st := &localStore{}
	for _, v := range []any{l, &l, s, &s, st, storeRedaction{}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%p"} {
			if strings.Contains(fmt.Sprintf(format, v), private) {
				t.Fatalf("format leaked private material from %T with %s", v, format)
			}
		}
		raw, e := json.Marshal(v)
		if e != nil || bytes.Contains(raw, []byte(private)) {
			t.Fatal("generic JSON leaked")
		}
	}
	raw, e := json.Marshal(ledgerDisk(*l.ledgerData))
	if e != nil || !bytes.Contains(raw, []byte(private)) {
		t.Fatal("private persistence codec changed")
	}
}

func TestTLSMalformedRejectionCannotEnableSecretCorrection(t *testing.T) {
	f := newClientFixture(t, "tls")
	f.malformedClaimError = true
	o := f.options()
	o.Secret = func(context.Context) ([]byte, error) {
		return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32))), nil
	}
	if _, e := Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var before ledger
	strictJSON(raw, &before)
	if before.ClaimDefinitelyRejected || before.AmbiguousClaimHash == "" {
		t.Fatal("malformed response authorized correction")
	}
	if _, e := Run(context.Background(), f.bootstrap, f.options()); !errors.Is(e, ErrInvitation) {
		t.Fatal(e)
	}
	raw, _ = os.ReadFile(filepath.Join(f.state, "ledger.json"))
	var after ledger
	strictJSON(raw, &after)
	if before.ClaimHash != after.ClaimHash || before.AmbiguousClaimHash != after.AmbiguousClaimHash || len(f.claims) != 1 {
		t.Fatal("malformed response changed semantic claim")
	}
}

func senderFixtureBinding(t *testing.T, c lanclient.Config) string {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(c.StateDirectory, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	var public struct {
		Binding string `json:"binding"`
	}
	if json.Unmarshal(raw, &public) != nil || !enrollmentcrypto.ValidHash(public.Binding) {
		t.Fatal("invalid fixture sender binding")
	}
	return public.Binding
}
func stageInterruptedPublication(t *testing.T, f *clientFixture) {
	t.Helper()
	p := filepath.Join(f.state, "ledger.json")
	raw, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var l ledger
	if strictJSON(raw, &l) != nil {
		t.Fatal("fixture ledger")
	}
	l.HandoffPrepared = false
	raw, e = json.Marshal(ledgerDisk(*l.ledgerData))
	if e != nil || os.WriteFile(p, raw, 0600) != nil {
		t.Fatal("fixture interrupted checkpoint")
	}
	for _, name := range []string{"agent.json", "ready.json"} {
		if e = os.Remove(filepath.Join(f.state, name)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestGuidedSenderBoundaryRejectsLostOrChangedDomainBeforeNetwork(t *testing.T) {
	for _, prepared := range []bool{true, false} {
		for _, mode := range []string{"empty-replacement", "missing-ledger", "missing-lock", "wrong-binding"} {
			t.Run(fmt.Sprintf("prepared=%t/%s", prepared, mode), func(t *testing.T) {
				f := newClientFixture(t, "http-test")
				o := f.options()
				result, e := Run(context.Background(), f.bootstrap, o)
				if e != nil {
					t.Fatal(e)
				}
				if !prepared {
					stageInterruptedPublication(t, f)
				}
				telemetry := result.Config.StateDirectory
				preserved := filepath.Join(t.TempDir(), "preserved")
				switch mode {
				case "empty-replacement":
					if e = os.Rename(telemetry, preserved); e != nil {
						t.Fatal(e)
					}
					if e = os.Mkdir(telemetry, 0700); e != nil {
						t.Fatal(e)
					}
				case "missing-ledger":
					if e = os.Rename(filepath.Join(telemetry, "state.json"), preserved); e != nil {
						t.Fatal(e)
					}
				case "missing-lock":
					if e = os.Rename(filepath.Join(telemetry, "state.lock"), preserved); e != nil {
						t.Fatal(e)
					}
				case "wrong-binding":
					p := filepath.Join(telemetry, "state.json")
					raw, e := os.ReadFile(p)
					if e != nil {
						t.Fatal(e)
					}
					var record map[string]json.RawMessage
					if json.Unmarshal(raw, &record) != nil {
						t.Fatal("fixture ledger")
					}
					record["binding"], _ = json.Marshal(strings.Repeat("f", 64))
					raw, _ = json.Marshal(record)
					if e = os.WriteFile(p, raw, 0600); e != nil {
						t.Fatal(e)
					}
				}
				entriesBefore, _ := os.ReadDir(telemetry)
				bytesBefore := map[string][]byte{}
				for _, entry := range entriesBefore {
					if entry.Type().IsRegular() {
						bytesBefore[entry.Name()], _ = os.ReadFile(filepath.Join(telemetry, entry.Name()))
					}
				}
				before := len(f.requests)
				if _, e = Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrState) {
					t.Fatal("lost/changed sender domain accepted", e)
				}
				if len(f.requests) != before {
					t.Fatal("invalid sender state opened network")
				}
				entriesAfter, _ := os.ReadDir(telemetry)
				if len(entriesAfter) != len(entriesBefore) {
					t.Fatal("validation created sender files")
				}
				for name, want := range bytesBefore {
					got, _ := os.ReadFile(filepath.Join(telemetry, name))
					if !bytes.Equal(got, want) {
						t.Fatal("validation changed sender bytes")
					}
				}
			})
		}
	}
}
func TestGuidedSenderLockBlocksEnrollmentResume(t *testing.T) {
	f := newClientFixture(t, "tls")
	o := f.options()
	result, e := Run(context.Background(), f.bootstrap, o)
	if e != nil {
		t.Fatal(e)
	}
	sender, e := lanclientstate.OpenExisting(result.Config.StateDirectory, senderFixtureBinding(t, result.Config))
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	before := len(f.requests)
	if _, e = Run(context.Background(), f.bootstrap, o); !errors.Is(e, ErrState) {
		t.Fatal("sender lock bypassed", e)
	}
	if len(f.requests) != before {
		t.Fatal("busy sender opened enrollment network")
	}
	if e = sender.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = Run(context.Background(), f.bootstrap, o); e != nil {
		t.Fatal("resume after sender close", e)
	}
}
func TestInitializedSenderResumesInterruptedPublicationWithoutReset(t *testing.T) {
	f := newClientFixture(t, "http-test")
	o := f.options()
	result, e := Run(context.Background(), f.bootstrap, o)
	if e != nil {
		t.Fatal(e)
	}
	expected, e := os.ReadFile(filepath.Join(result.Config.StateDirectory, "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	stageInterruptedPublication(t, f)
	if _, e = Run(context.Background(), f.bootstrap, o); e != nil {
		t.Fatal(e)
	}
	got, _ := os.ReadFile(filepath.Join(result.Config.StateDirectory, "state.json"))
	if !bytes.Equal(got, expected) {
		t.Fatal("interrupted publication reset sender state")
	}
	if _, e = os.Stat(filepath.Join(f.state, "ready.json")); e != nil {
		t.Fatal("ready marker not republished")
	}
}

func TestEnrollmentValidationPreservesSenderCrashTemporary(t *testing.T) {
	f := newClientFixture(t, "http-test")
	o := f.options()
	result, e := Run(context.Background(), f.bootstrap, o)
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(result.Config.StateDirectory, ".state.tmp")
	sentinel := []byte("synthetic uncommitted sender temporary")
	if e = os.WriteFile(p, sentinel, 0600); e != nil {
		t.Fatal(e)
	}
	_, e = Run(context.Background(), f.bootstrap, o)
	if e != nil && !errors.Is(e, ErrState) {
		t.Fatal("unexpected validation result", e)
	}
	got, readErr := os.ReadFile(p)
	if readErr != nil || !bytes.Equal(got, sentinel) {
		t.Fatal("enrollment validation removed or changed sender temporary")
	}
}
