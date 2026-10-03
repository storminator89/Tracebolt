package enrollmenttransport

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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/bundle"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/signedhttp"
)

func id(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }

type fixture struct {
	store     *enrollmentstore.Store
	path      string
	config    enrollmentstate.Config
	issuer    *enrollmentissuer.Issuer
	root      *x509.Certificate
	rootKey   ed25519.PrivateKey
	key       ed25519.PrivateKey
	cert      enrollmentcrypto.VerifiedCertificate
	snapshot  enrollmentstate.Snapshot
	challenge enrollmentcrypto.ChallengeContext
	pair      tls.Certificate
	server    tls.Certificate
	now       time.Time
}

func key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}
func makeCertificate(t *testing.T, template, parent *x509.Certificate, public ed25519.PublicKey, key ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func newFixture(t *testing.T, profile string, activate bool) *fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rp, rk := key(t)
	ip, ik := key(t)
	rh, ih := sha256.Sum256(rp), sha256.Sum256(ip)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	root := makeCertificate(t, rt, rt, rp, rk)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Ephemeral dedicated issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	issuerCert := makeCertificate(t, it, root, ip, rk)
	ihash := sha256.Sum256(issuerCert.Raw)
	issuer, err := enrollmentissuer.New(issuerCert.Raw, root.Raw, ik, hex.EncodeToString(ihash[:]), now)
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://manager.test"
	if profile == "http-test" {
		origin = "http://manager.test"
	}
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: id("manager", 1), Origin: origin, Profile: profile, CollectionProfile: enrollmentcrypto.CollectionProfile, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = MaxRecords, MaxRecords, MaxRecords
	f := &fixture{path: filepath.Join(t.TempDir(), "private", "enrollment.sqlite"), config: cfg, issuer: issuer, root: root, rootKey: rk, now: now}
	f.store, err = enrollmentstore.Open(f.path, cfg, issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	_, f.key = key(t)
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{32}, 32))
	hash, _ := enrollmentcrypto.InvitationHash(secret)
	ctx := context.Background()
	f.snapshot, err = f.store.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: id("invite", 1), RequestID: id("request", 1), InvitationHash: hex.EncodeToString(hash[:]), Platform: "linux", Now: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	f.challenge = enrollmentcrypto.ChallengeContext{ManagerInstanceID: cfg.Binding.InstanceID, Profile: profile, Origin: origin, CollectionProfile: cfg.Binding.CollectionProfile, InvitationID: f.snapshot.InvitationID, ClaimID: id("claim", 1), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{77}, 32)), ExpiresAt: now.Unix() + 60}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, f.key)
	if err != nil {
		t.Fatal(err)
	}
	message, err := enrollmentcrypto.ClaimSigningMessage(f.challenge, id("request", 2), csr, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	c := f.challenge
	raw, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.ManagerInstanceID, "profile": profile, "origin": origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "requestId": id("request", 2), "challenge": c.Challenge, "invitationSecret": secret, "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	claim, err := enrollmentcrypto.VerifyClaim(raw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(2), ClaimID: c.ClaimID}, claim)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(3), DeviceID: id("agent", 1), KeyFingerprint: claim.KeyFingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: f.control(4), IntentID: id("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: now.Unix() - 30, NotAfter: now.Add(24 * time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	intent, err := f.store.SigningIntent(ctx, f.snapshot.InvitationID, now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	f.cert, err = issuer.Sign(ctx, intent, now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.CommitIssued(ctx, f.control(5), f.cert)
	if err != nil {
		t.Fatal(err)
	}
	f.pair = tls.Certificate{Certificate: [][]byte{f.cert.DER(), issuer.IssuerDER()}, PrivateKey: f.key}
	sp, sk := key(t)
	server := makeCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Ephemeral server"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, root, sp, rk)
	f.server = tls.Certificate{Certificate: [][]byte{server.Raw}, PrivateKey: sk}
	if activate {
		f.activate(t)
	}
	return f
}
func (f *fixture) control(n int) enrollmentstate.Control {
	return enrollmentstate.Control{InvitationID: f.snapshot.InvitationID, RequestID: id("request", n), ExpectedRevision: f.snapshot.Revision, Now: f.now.Unix()}
}
func (f *fixture) activate(t *testing.T) {
	t.Helper()
	c := f.control(6)
	i := f.cert.Intent()
	message, err := enrollmentcrypto.ActivationSigningMessage(f.challenge, i, c.RequestID, f.cert.CertificateHash(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": i.ManagerInstanceID, "profile": i.Profile, "origin": i.Origin, "deviceId": i.DeviceID, "intentId": i.IntentID, "certificateHash": f.cert.CertificateHash(), "requestId": c.RequestID, "challenge": f.challenge.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	proof, err := enrollmentcrypto.VerifyActivation(raw, f.cert, f.challenge, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Activate(context.Background(), c, proof)
	if err != nil {
		t.Fatal(err)
	}
}
func (f *fixture) revoke(t *testing.T) {
	t.Helper()
	other, err := enrollmentstore.Open(f.path, f.config, f.issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	control := f.control(30)
	control.Now = time.Now().UTC().Unix()
	f.snapshot, err = other.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: control, State: enrollmentstate.Revoked})
	if err != nil {
		t.Fatal(err)
	}
}
func frame(t *testing.T, sequence uint64, at time.Time) []byte {
	t.Helper()
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "Disposable fixture", CollectedAt: at}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Fixture OS", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: at, AgentVersion: "test", CPU: metric, Memory: metric, Disk: metric, Uptime: "unknown", Tags: []string{"read-only"}, Capabilities: []model.Capability{}, Evidence: []model.Evidence{}, Trend: []float64{}, CaseIDs: []string{}}
	b := bundle.Bundle{SchemaVersion: bundle.SchemaVersion, Product: "Tracebolt", Version: "test", GeneratedAt: at, Platform: "linux", Architecture: "amd64", Scope: "single-read-only-local-observation", Privacy: []string{}, Observation: d}
	raw, err := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: sequence, Observation: b})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = lanstore.ValidateFrame(raw, at); err != nil {
		t.Fatal(err)
	}
	return raw
}
func (f *fixture) listen(t *testing.T, wrap func(http.Handler) http.Handler) (*Ingress, *httptest.Server, *http.Client) {
	t.Helper()
	s := httptest.NewUnstartedServer(nil)
	origin := "https://" + s.Listener.Addr().String()
	if f.config.Binding.Profile == "http-test" {
		origin = "http://" + s.Listener.Addr().String()
	}
	h, err := New(f.store, f.issuer.IssuerDER(), origin)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Handler = h
	if wrap != nil {
		s.Config.Handler = wrap(h)
	}
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	transport := &http.Transport{Proxy: nil}
	if f.config.Binding.Profile == "tls" {
		s.TLS, err = h.TLSConfig(f.server)
		if err != nil {
			t.Fatal(err)
		}
		s.StartTLS()
		roots := x509.NewCertPool()
		roots.AddCert(f.root)
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{f.pair}}
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	t.Cleanup(transport.CloseIdleConnections)
	return h, s, &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (f *fixture) request(t *testing.T, origin string, sequence uint64, at time.Time, body []byte) *http.Request {
	t.Helper()
	if f.config.Binding.Profile == "http-test" {
		r, err := signedhttp.NewSignedRequest(context.Background(), origin, f.pair, sequence, at, body)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r, err := http.NewRequest(http.MethodPost, origin+signedhttp.Path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	return r
}
func response(t *testing.T, client *http.Client, r *http.Request, want int) []byte {
	t.Helper()
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != want {
		t.Fatalf("status %d, want %d: %s", res.StatusCode, want, raw)
	}
	return raw
}
