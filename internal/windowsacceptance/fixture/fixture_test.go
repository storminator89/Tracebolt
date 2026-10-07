package fixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/operational"
)

// These tests deliberately do not call Start. Their keys, certificates, proofs,
// clocks and Windows-shaped samples are disposable in-memory inventions, never
// native enrollment, OS telemetry, an installed service, ACLs, or a TLS handshake.
type syntheticClient struct {
	f                                        *Fixture
	t                                        *testing.T
	now                                      *time.Time
	key                                      ed25519.PrivateKey
	public, csr                              []byte
	claimID, claimRequest, activationRequest string
	cert                                     enrollmentcrypto.VerifiedCertificate
}

func synthetic(t *testing.T) *syntheticClient {
	t.Helper()
	now := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	f, e := newFixture(context.Background(), "https://127.0.0.1:18443", "https://127.0.0.1:18444", func() time.Time { return now })
	if e != nil {
		t.Fatal("create disposable in-memory fixture:", e)
	}
	t.Cleanup(func() { _ = f.Close() })
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal("synthetic key generation failed")
	}
	t.Cleanup(func() { clear(key) })
	public, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		t.Fatal("synthetic public key encoding failed")
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		t.Fatal("synthetic CSR creation failed")
	}
	return &syntheticClient{f: f, t: t, now: &now, key: key, public: public, csr: csr, claimID: id(t, "claim_"), claimRequest: id(t, "request_"), activationRequest: id(t, "request_")}
}

func id(t *testing.T, prefix string) string {
	t.Helper()
	v, e := randomID(prefix)
	if e != nil {
		t.Fatal("synthetic identifier generation failed")
	}
	return v
}
func encoded(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal("synthetic encoding failed")
	}
	return raw
}

func (c *syntheticClient) request(path string, raw []byte, peer bool) *http.Request {
	c.t.Helper()
	origin := c.f.Bootstrap().EnrollmentOrigin
	if path == telemetryPath {
		origin = c.f.Bootstrap().AgentOrigin
	}
	r, e := http.NewRequest(http.MethodPost, origin+path, bytes.NewReader(raw))
	if e != nil {
		c.t.Fatal("synthetic request creation failed")
	}
	r.RemoteAddr = "127.0.0.1:20000"
	r.Header.Set("Content-Type", "application/json")
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	if peer {
		leaf, e := x509.ParseCertificate(c.cert.DER())
		if e != nil {
			c.t.Fatal("synthetic certificate missing")
		}
		chains, e := leaf.Verify(x509.VerifyOptions{Roots: c.f.state.clientRoots, CurrentTime: *c.now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if e != nil {
			c.t.Fatal("synthetic certificate chain invalid")
		}
		r.TLS.PeerCertificates = []*x509.Certificate{leaf}
		r.TLS.VerifiedChains = chains
	}
	return r
}

func (c *syntheticClient) post(path string, raw []byte, peer bool) *httptest.ResponseRecorder {
	c.t.Helper()
	r := c.request(path, raw, peer)
	w := httptest.NewRecorder()
	c.f.serve(w, r, path == telemetryPath)
	return w
}

func (c *syntheticClient) challenge(purpose string) enrollmentcrypto.ChallengeContext {
	c.t.Helper()
	raw := encoded(c.t, map[string]string{"invitationId": c.f.Bootstrap().InvitationID, "claimId": c.claimID, "purpose": purpose})
	w := c.post(prefix+"challenge", raw, false)
	if w.Code != 200 {
		c.t.Fatal("synthetic challenge rejected, status", w.Code)
	}
	var out struct {
		SchemaVersion string
		Context       enrollmentcrypto.ChallengeContext
		Purpose       string
		ServerNow     time.Time
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.SchemaVersion != "tracebolt.enrollment-challenge.v2" || out.Purpose != purpose || !out.ServerNow.Equal(*c.now) {
		c.t.Fatal("challenge envelope invalid")
	}
	return out.Context
}

func base(cc enrollmentcrypto.ChallengeContext) map[string]string {
	return map[string]string{"managerInstanceId": cc.ManagerInstanceID, "profile": cc.Profile, "origin": cc.Origin, "collectionProfile": cc.CollectionProfile, "invitationId": cc.InvitationID, "claimId": cc.ClaimID, "challenge": cc.Challenge}
}

func (c *syntheticClient) claimBytes(cc enrollmentcrypto.ChallengeContext) []byte {
	c.t.Helper()
	secret, e := c.f.Secret(context.Background())
	if e != nil {
		c.t.Fatal("synthetic secret callback failed")
	}
	defer clear(secret)
	message, e := enrollmentcrypto.ClaimSigningMessage(cc, c.claimRequest, c.csr, string(secret), *c.now)
	if e != nil {
		c.t.Fatal("synthetic claim message failed")
	}
	defer clear(message)
	fields := base(cc)
	fields["schemaVersion"] = enrollmentcrypto.ClaimVersion
	fields["requestId"] = c.claimRequest
	fields["invitationSecret"] = string(secret)
	fields["csr"] = base64.RawStdEncoding.EncodeToString(c.csr)
	fields["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(c.key, message))
	return encoded(c.t, fields)
}

func (c *syntheticClient) claim() {
	c.t.Helper()
	raw := c.claimBytes(c.challenge("claim"))
	defer clear(raw)
	w := c.post(prefix+"claim", raw, false)
	if w.Code != 200 {
		c.t.Fatal("synthetic claim rejected, status", w.Code)
	}
	v, e := enrollmentstate.DecodeSnapshot(w.Body.Bytes())
	if e != nil || v.State != enrollmentstate.ClaimedPending || v.Platform != "windows" {
		c.t.Fatal("claim did not remain pending")
	}
}

func (c *syntheticClient) statusBytes(purpose string) []byte {
	c.t.Helper()
	cc := c.challenge(purpose)
	request := id(c.t, "request_")
	message, e := enrollmentcrypto.StatusSigningMessage(cc, purpose, request, c.public, *c.now)
	if e != nil {
		c.t.Fatal("synthetic status message failed")
	}
	fields := base(cc)
	fields["schemaVersion"] = enrollmentcrypto.StatusVersion
	fields["requestId"] = request
	fields["keyFingerprint"] = digest(c.public)
	fields["purpose"] = purpose
	fields["proof"] = base64.RawStdEncoding.EncodeToString(ed25519.Sign(c.key, message))
	return encoded(c.t, fields)
}

func (c *syntheticClient) approve() {
	c.t.Helper()
	code, e := enrollmentcrypto.ComparisonCode(c.f.Bootstrap().ManagerInstanceID, c.f.Bootstrap().InvitationID, c.claimID, digest(c.public))
	if e != nil {
		c.t.Fatal("synthetic comparison failed")
	}
	if e = c.f.Approve(digest(c.public), code); e != nil {
		c.t.Fatal("synthetic exact approval failed:", e)
	}
	w := c.post(prefix+"credential", c.statusBytes("credential"), false)
	if w.Code != 200 {
		c.t.Fatal("synthetic credential delivery rejected")
	}
	var out struct {
		SchemaVersion  string
		CertificateDER string
		IssuerDER      string
		Intent         enrollmentcrypto.Intent
	}
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.SchemaVersion != "tracebolt.enrollment-credential.v2" {
		c.t.Fatal("credential envelope invalid")
	}
	der, e := base64.RawStdEncoding.DecodeString(out.CertificateDER)
	if e != nil {
		c.t.Fatal("synthetic credential encoding invalid")
	}
	issuer, e := base64.RawStdEncoding.DecodeString(out.IssuerDER)
	if e != nil {
		c.t.Fatal("synthetic issuer encoding invalid")
	}
	c.cert, e = enrollmentcrypto.VerifyIssued(der, issuer, out.Intent, *c.now)
	if e != nil {
		c.t.Fatal("real credential contract rejected synthetic credential")
	}
}

func (c *syntheticClient) activationBytes() []byte {
	c.t.Helper()
	cc := c.challenge("activation")
	intent := c.cert.Intent()
	message, e := enrollmentcrypto.ActivationSigningMessage(cc, intent, c.activationRequest, c.cert.CertificateHash(), *c.now)
	if e != nil {
		c.t.Fatal("synthetic activation message failed")
	}
	return encoded(c.t, map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": cc.ManagerInstanceID, "profile": cc.Profile, "origin": cc.Origin, "deviceId": intent.DeviceID, "intentId": intent.IntentID, "certificateHash": c.cert.CertificateHash(), "requestId": c.activationRequest, "challenge": cc.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(c.key, message))})
}

func (c *syntheticClient) activate() {
	c.t.Helper()
	w := c.post(prefix+"activate", c.activationBytes(), false)
	if w.Code != 200 || c.f.Snapshot().State != enrollmentstate.Activated {
		c.t.Fatal("synthetic activation rejected")
	}
}

func inventedFrame(platform string, seq uint64, at time.Time) lanstore.Frame {
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Invented fixture value; no collector", CollectedAt: at}
	d := model.Device{ID: "local-windows", Name: "Local Windows", Platform: platform, OS: "Invented Windows fixture", Site: "Local machine", Group: "Local observations", Status: "unknown", Source: "local", LastSeen: at, AgentVersion: "fixture", CPU: metric, Memory: metric, Disk: metric, Uptime: "unknown", Tags: []string{"read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	if platform == "linux" {
		d.ID = "sandbox-local"
		d.Name = "Local sandbox"
		d.Source = "sandbox"
		d.Site = "Cloud sandbox"
	}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "fixture", GeneratedAt: at, Platform: platform, Architecture: "amd64", Scope: "single-read-only-local-observation", Validation: bundle.Validation{PlatformExecution: "Invented test data; no native collector", Acceptance: "No native acceptance"}, Privacy: []string{}, Observation: d}
	return lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: seq, Observation: b}
}

func receipt(t *testing.T, w *httptest.ResponseRecorder) lanstore.Receipt {
	t.Helper()
	var r lanstore.Receipt
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &r) != nil {
		t.Fatal("synthetic receipt rejected, status", w.Code)
	}
	return r
}

func TestSyntheticRealProofLifecycleAndReceipt(t *testing.T) {
	c := synthetic(t)
	if c.f.Snapshot().State != enrollmentstate.Created || c.f.Evidence().Frames != 0 {
		t.Fatal("new fixture already authorized")
	}
	if w := c.post(prefix+"status", c.statusBytes("status"), false); w.Code != 401 {
		t.Fatal("unclaimed status must reject possession")
	}
	c.claim()
	pending := c.f.Snapshot()
	for _, pair := range [][2]string{{"", ""}, {digest(c.public), strings.Repeat("0", 32)}, {strings.Repeat("1", 64), pending.Claim.ComparisonCode}} {
		if c.f.Approve(pair[0], pair[1]) == nil || c.f.Snapshot() != pending {
			t.Fatal("mismatched approval changed lifecycle")
		}
	}
	if w := c.post(prefix+"credential", c.statusBytes("credential"), false); w.Code != 409 {
		t.Fatal("unapproved credential delivery accepted")
	}
	c.approve()
	if w := c.post(telemetryPath, encoded(t, inventedFrame("windows", 1, *c.now)), true); w.Code != 403 {
		t.Fatal("preactivation telemetry accepted")
	}
	c.activate()
	firstRaw := encoded(t, inventedFrame("windows", 1, *c.now))
	defer clear(firstRaw)
	if w := c.post(telemetryPath, firstRaw, false); w.Code != 403 {
		t.Fatal("telemetry without peer certificate accepted")
	}
	first := receipt(t, c.post(telemetryPath, firstRaw, true))
	if first.SchemaVersion != "tracebolt.agent-receipt.v1" || first.AgentID != c.cert.Intent().DeviceID || first.Sequence != 1 || first.Duplicate || !first.CollectedAt.Equal(*c.now) || !first.ReceivedAt.Equal(*c.now) {
		t.Fatal("receipt did not bind accepted frame")
	}
	*c.now = c.now.Add(time.Second)
	duplicate := receipt(t, c.post(telemetryPath, firstRaw, true))
	if !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(first.ReceivedAt) || !duplicate.CollectedAt.Equal(first.CollectedAt) {
		t.Fatal("duplicate refreshed original receipt")
	}
	if w := c.post(telemetryPath, encoded(t, inventedFrame("windows", 1, *c.now)), true); w.Code != 409 {
		t.Fatal("same sequence equivocation accepted")
	}
	for _, kind := range []string{"wrong-platform", "managed"} {
		frame := inventedFrame("linux", 2, *c.now)
		if kind == "managed" {
			op := operational.Empty(*c.now, operational.ReasonNotImplemented)
			frame.SchemaVersion = lanstore.FrameOperationalVersion
			frame.Operational = &op
		}
		raw := encoded(t, frame)
		if _, e := lanstore.ValidateFrame(raw, *c.now); e != nil {
			t.Fatal("wrong-scope test must start schema-valid")
		}
		if w := c.post(telemetryPath, raw, true); w.Code != 400 {
			t.Fatal("wrong platform/profile admitted")
		}
	}
	before := c.f.Snapshot()
	c.f.ToggleUnavailable(true)
	if w := c.post(telemetryPath, encoded(t, inventedFrame("windows", 2, *c.now)), true); w.Code != 503 {
		t.Fatal("outage accepted telemetry")
	}
	if c.f.Evidence().Frames != 1 || c.f.Evidence().UnavailableRequests != 1 || c.f.Snapshot() != before {
		t.Fatal("outage altered identity or counters")
	}
	c.f.ToggleUnavailable(false)
	second := receipt(t, c.post(telemetryPath, encoded(t, inventedFrame("windows", 2, *c.now)), true))
	if second.Sequence != 2 || second.AgentID != first.AgentID || c.f.Evidence().Frames != 2 || c.f.Evidence().DuplicateReceipts != 1 {
		t.Fatal("outage resume lost identity or sequence")
	}
}

func TestSyntheticChallengeUseExpiryAndCapacity(t *testing.T) {
	c := synthetic(t)
	cc := c.challenge("claim")
	raw := c.claimBytes(cc)
	defer clear(raw)
	if w := c.post(prefix+"claim", raw, false); w.Code != 200 {
		t.Fatal("first proof failed")
	}
	if w := c.post(prefix+"claim", raw, false); w.Code != 401 {
		t.Fatal("replayed challenge accepted")
	}
	cc = c.challenge("claim")
	raw2 := c.claimBytes(cc)
	defer clear(raw2)
	*c.now = c.now.Add(61 * time.Second)
	if w := c.post(prefix+"claim", raw2, false); w.Code != 401 {
		t.Fatal("expired proof accepted")
	}
	for i := 0; i < MaxChallenges; i++ {
		c.challenge("status")
	}
	challengeRaw := encoded(t, map[string]string{"invitationId": c.f.Bootstrap().InvitationID, "claimId": c.claimID, "purpose": "status"})
	if w := c.post(prefix+"challenge", challengeRaw, false); w.Code != 429 {
		t.Fatal("challenge capacity unbounded")
	}
	*c.now = c.now.Add(61 * time.Second)
	c.challenge("status")
}

func TestSyntheticRequestsRemainFixedAndBounded(t *testing.T) {
	c := synthetic(t)
	raw := encoded(t, map[string]string{"invitationId": c.f.Bootstrap().InvitationID, "claimId": c.claimID, "purpose": "claim"})
	changes := map[string]func(*http.Request){
		"query": func(r *http.Request) { r.URL.RawQuery = "extra=1" }, "method": func(r *http.Request) { r.Method = "GET" },
		"host": func(r *http.Request) { r.Host = "example.test" }, "route": func(r *http.Request) { r.URL.Path = "/api/approve" },
		"TLS missing": func(r *http.Request) { r.TLS = nil }, "TLS 1.2": func(r *http.Request) { r.TLS.Version = tls.VersionTLS12 },
		"non-loopback": func(r *http.Request) { r.RemoteAddr = "192.0.2.1:4567" }, "cookies": func(r *http.Request) { r.Header.Set("Cookie", "invented") },
		"proxy": func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }, "signed fallback": func(r *http.Request) { r.Header.Set("X-Tracebolt-Signature", "invented") },
		"duplicate content type": func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, "compressed": func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		"too big": func(r *http.Request) { r.ContentLength = enrollmentcrypto.MaxClaimBytes + 1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			r := c.request(prefix+"challenge", raw, false)
			change(r)
			w := httptest.NewRecorder()
			c.f.serve(w, r, false)
			if w.Code < 400 {
				t.Fatal("request bypassed fixed boundary")
			}
		})
	}
	for _, bad := range []string{`{"invitationId":"a","invitationId":"b","claimId":"c","purpose":"claim"}`, `{"invitationId":"a","claimId":"b","purpose":"claim","unknown":"x"}`, `{"invitationId":null,"claimId":"b","purpose":"claim"}`} {
		if w := c.post(prefix+"challenge", []byte(bad), false); w.Code != 400 {
			t.Fatal("non-strict challenge accepted")
		}
	}
	if c.f.Evidence().Frames != 0 || c.f.Snapshot().State != enrollmentstate.Created {
		t.Fatal("invalid routes caused state changes")
	}
}

func TestSyntheticFrameAndRequestCaps(t *testing.T) {
	c := synthetic(t)
	c.claim()
	c.approve()
	c.activate()
	for i := uint64(1); i <= MaxFrames; i++ {
		*c.now = c.now.Add(time.Second)
		receipt(t, c.post(telemetryPath, encoded(t, inventedFrame("windows", i, *c.now)), true))
	}
	*c.now = c.now.Add(time.Second)
	if w := c.post(telemetryPath, encoded(t, inventedFrame("windows", MaxFrames+1, *c.now)), true); w.Code != 503 || c.f.Evidence().Frames != MaxFrames {
		t.Fatal("frame capacity unbounded")
	}
	c.f.state.mu.Lock()
	c.f.state.requests = MaxRequests
	c.f.state.mu.Unlock()
	if w := c.post(telemetryPath, encoded(t, inventedFrame("windows", MaxFrames+1, *c.now)), true); w.Code != 503 || c.f.Evidence().Requests != MaxRequests {
		t.Fatal("request capacity unbounded")
	}
}

func TestRedactionSecretCopiesAndClosedFixture(t *testing.T) {
	c := synthetic(t)
	a, e := c.f.Secret(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer clear(a)
	b, e := c.f.Secret(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer clear(b)
	a[0] ^= 1
	if bytes.Equal(a, b) {
		t.Fatal("callback shares mutable secret")
	}
	var log bytes.Buffer
	slog.New(slog.NewJSONHandler(&log, nil)).Info("synthetic fixture", "fixture", c.f)
	jsonPointer, _ := json.Marshal(c.f)
	jsonValue, _ := json.Marshal(*c.f)
	for _, out := range []string{fmt.Sprintf("%+v", c.f), fmt.Sprintf("%#v", *c.f), string(jsonPointer), string(jsonValue), log.String()} {
		if strings.Contains(out, string(b)) || !strings.Contains(strings.ToLower(out), "redacted") {
			t.Fatal("fixture formatting exposed material")
		}
	}
	if e = c.f.Close(); e != nil {
		t.Fatal(e)
	}
	if e = c.f.Close(); e != nil {
		t.Fatal("close not idempotent")
	}
	if _, e = c.f.Secret(context.Background()); e == nil {
		t.Fatal("closed fixture released secret")
	}
	if !c.f.Evidence().Closed || c.f.state.issuer != nil || len(c.f.state.secret) != 0 {
		t.Fatal("closed fixture retained signing handle or invitation")
	}
}

func TestConcurrentSyntheticObservationAndClose(t *testing.T) {
	c := synthetic(t)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = c.f.Evidence()
				_ = c.f.Snapshot()
				_ = c.f.Bootstrap()
				secret, _ := c.f.Secret(context.Background())
				clear(secret)
				c.f.ToggleUnavailable(j%2 == 0)
			}
		}()
	}
	_ = c.f.Close()
	wg.Wait()
}

func TestSyntheticWrongProofAndPurposeConsumeChallenge(t *testing.T) {
	c := synthetic(t)
	cc := c.challenge("claim")
	raw := c.claimBytes(cc)
	defer clear(raw)
	var fields map[string]string
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("synthetic proof decoding failed")
	}
	fields["proof"] = base64.RawStdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	corrupt := encoded(t, fields)
	delete(fields, "invitationSecret")
	defer clear(corrupt)
	if w := c.post(prefix+"claim", corrupt, false); w.Code != 401 {
		t.Fatal("invalid possession accepted")
	}
	if w := c.post(prefix+"claim", raw, false); w.Code != 401 {
		t.Fatal("failed proof did not consume challenge")
	}
	c.claim()
	status := c.statusBytes("status")
	if w := c.post(prefix+"credential", status, false); w.Code != 401 {
		t.Fatal("status proof crossed purpose boundary")
	}
	if w := c.post(prefix+"status", status, false); w.Code != 401 {
		t.Fatal("wrong-purpose use did not consume challenge")
	}
}

func TestSyntheticOriginalPendingDeadlineAndCertificateRoles(t *testing.T) {
	c := synthetic(t)
	c.claim()
	pending := c.f.Snapshot()
	if pending.DeadlineAt-pending.Claim.At != int64(30*time.Minute/time.Second) {
		t.Fatal("fixture shortened the actual enrollment pending lifetime")
	}
	server, e := x509.ParseCertificate(c.f.state.server.Certificate[0])
	if e != nil || len(server.IPAddresses) != 1 || server.IPAddresses[0].String() != "127.0.0.1" || len(server.DNSNames) != 0 || len(server.ExtKeyUsage) != 1 || server.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatal("fixture server certificate exceeds loopback/server scope")
	}
	issuer := c.f.state.issuerCert
	if len(issuer.ExtKeyUsage) != 1 || issuer.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || !issuer.MaxPathLenZero || issuer.MaxPathLen != 0 {
		t.Fatal("fixture issuer exceeds dedicated client-only authority")
	}
	*c.now = time.Unix(pending.DeadlineAt, 0).UTC()
	if c.f.Approve(pending.Claim.KeyFingerprint, pending.Claim.ComparisonCode) == nil || c.f.Snapshot() != pending {
		t.Fatal("fake-clock expired pending identity was approved or reset")
	}
}

func TestSyntheticNewSequenceRequiresStrictlyLaterTimesLikeProductionStore(t *testing.T) {
	c := synthetic(t)
	c.claim()
	c.approve()
	c.activate()
	at := *c.now
	first := inventedFrame("windows", 1, at)
	first.Observation.GeneratedAt = at.Add(2 * time.Second)
	*c.now = at.Add(3 * time.Second)
	receipt(t, c.post(telemetryPath, encoded(t, first), true))
	for _, same := range []string{"collected", "generated", "both"} {
		frame := inventedFrame("windows", 2, at.Add(time.Second))
		frame.Observation.GeneratedAt = *c.now
		if same == "collected" || same == "both" {
			frame = inventedFrame("windows", 2, at)
			frame.Observation.GeneratedAt = *c.now
		}
		if same == "generated" || same == "both" {
			frame.Observation.GeneratedAt = first.Observation.GeneratedAt
		}
		raw := encoded(t, frame)
		if _, err := lanstore.ValidateFrame(raw, *c.now); err != nil {
			t.Fatal("timestamp regression must be schema valid")
		}
		if w := c.post(telemetryPath, raw, true); w.Code != 409 || c.f.Evidence().Frames != 1 {
			t.Fatal("fixture admitted replay rejected by production store")
		}
	}
	receipt(t, c.post(telemetryPath, encoded(t, inventedFrame("windows", 2, *c.now)), true))
}
