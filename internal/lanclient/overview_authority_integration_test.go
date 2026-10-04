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
	"localrmm/internal/completeoverview"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/enrollmenttransport"
	"localrmm/internal/overviewledger"
	"localrmm/internal/overviewwire"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// All identities, files, observations and listeners in this file are disposable.
// The source callback returns invented rows; no host collector or service runs.
func overviewAuthorityID(prefix string, n int) string { return fmt.Sprintf("%s_%032x", prefix, n) }

type overviewAuthorityFixture struct {
	store                *enrollmentstore.Store
	path                 string
	config               enrollmentstate.Config
	issuer               *enrollmentissuer.Issuer
	root                 *x509.Certificate
	rootKey              ed25519.PrivateKey
	overviewAuthorityKey ed25519.PrivateKey
	cert                 enrollmentcrypto.VerifiedCertificate
	snapshot             enrollmentstate.Snapshot
	challenge            enrollmentcrypto.ChallengeContext
	pair                 tls.Certificate
	server               tls.Certificate
	now                  time.Time
}

func overviewAuthorityKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return p, k
}
func overviewAuthorityCertificate(t *testing.T, template, parent *x509.Certificate, public ed25519.PublicKey, overviewAuthorityKey ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, overviewAuthorityKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func newOverviewAuthorityFixture(t *testing.T, profile, collection string, activate bool) *overviewAuthorityFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rp, rk := overviewAuthorityKey(t)
	ip, ik := overviewAuthorityKey(t)
	rh, ih := sha256.Sum256(rp), sha256.Sum256(ip)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Ephemeral root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	root := overviewAuthorityCertificate(t, rt, rt, rp, rk)
	it := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Ephemeral dedicated issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	issuerCert := overviewAuthorityCertificate(t, it, root, ip, rk)
	ihash := sha256.Sum256(issuerCert.Raw)
	issuer, err := enrollmentissuer.New(issuerCert.Raw, root.Raw, ik, hex.EncodeToString(ihash[:]), now)
	if err != nil {
		t.Fatal(err)
	}
	origin := "https://manager.test"
	if profile == "http-test" {
		origin = "http://manager.test"
	}
	cfg := enrollmentstate.DefaultConfig(enrollmentstate.Binding{InstanceID: overviewAuthorityID("manager", 1), Origin: origin, Profile: profile, CollectionProfile: collection, IssuerFingerprint: issuer.Fingerprint()})
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
	f := &overviewAuthorityFixture{path: filepath.Join(t.TempDir(), "private", "enrollment.sqlite"), config: cfg, issuer: issuer, root: root, rootKey: rk, now: now}
	f.store, err = enrollmentstore.Open(f.path, cfg, issuer.IssuerDER())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.store.Close() })
	_, f.overviewAuthorityKey = overviewAuthorityKey(t)
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{32}, 32))
	hash, _ := enrollmentcrypto.InvitationHash(secret)
	ctx := context.Background()
	f.snapshot, err = f.store.CreateInvitation(ctx, enrollmentstate.CreateCommand{InvitationID: overviewAuthorityID("invite", 1), RequestID: overviewAuthorityID("request", 1), InvitationHash: hex.EncodeToString(hash[:]), Platform: "linux", Now: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	f.challenge = enrollmentcrypto.ChallengeContext{ManagerInstanceID: cfg.Binding.InstanceID, Profile: profile, Origin: origin, CollectionProfile: cfg.Binding.CollectionProfile, InvitationID: f.snapshot.InvitationID, ClaimID: overviewAuthorityID("claim", 1), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{77}, 32)), ExpiresAt: now.Unix() + 60}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, f.overviewAuthorityKey)
	if err != nil {
		t.Fatal(err)
	}
	message, err := enrollmentcrypto.ClaimSigningMessage(f.challenge, overviewAuthorityID("request", 2), csr, secret, now)
	if err != nil {
		t.Fatal(err)
	}
	c := f.challenge
	raw, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.ManagerInstanceID, "profile": profile, "origin": origin, "collectionProfile": c.CollectionProfile, "invitationId": c.InvitationID, "claimId": c.ClaimID, "requestId": overviewAuthorityID("request", 2), "challenge": c.Challenge, "invitationSecret": secret, "csr": base64.RawStdEncoding.EncodeToString(csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.overviewAuthorityKey, message))})
	claim, err := enrollmentcrypto.VerifyClaim(raw, c, now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Claim(ctx, enrollmentstate.ClaimCommand{Control: f.control(2), ClaimID: c.ClaimID}, claim)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Approve(ctx, enrollmentstate.ApproveCommand{Control: f.control(3), DeviceID: overviewAuthorityID("agent", 1), KeyFingerprint: claim.KeyFingerprint()})
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.BeginIssuance(ctx, enrollmentstate.IntentCommand{Control: f.control(4), IntentID: overviewAuthorityID("intent", 1), SerialHex: fmt.Sprintf("%032x", 1), TemplateVersion: enrollmentcrypto.TemplateVersion, NotBefore: now.Unix() - 30, NotAfter: now.Add(24 * time.Hour).Unix()})
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
	f.pair = tls.Certificate{Certificate: [][]byte{f.cert.DER(), issuer.IssuerDER()}, PrivateKey: f.overviewAuthorityKey}
	sp, sk := overviewAuthorityKey(t)
	server := overviewAuthorityCertificate(t, &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Ephemeral server"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}, root, sp, rk)
	f.server = tls.Certificate{Certificate: [][]byte{server.Raw}, PrivateKey: sk}
	if activate {
		f.activate(t)
	}
	return f
}
func (f *overviewAuthorityFixture) control(n int) enrollmentstate.Control {
	return enrollmentstate.Control{InvitationID: f.snapshot.InvitationID, RequestID: overviewAuthorityID("request", n), ExpectedRevision: f.snapshot.Revision, Now: f.now.Unix()}
}
func (f *overviewAuthorityFixture) activate(t *testing.T) {
	t.Helper()
	c := f.control(6)
	i := f.cert.Intent()
	message, err := enrollmentcrypto.ActivationSigningMessage(f.challenge, i, c.RequestID, f.cert.CertificateHash(), f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ActivationVersion, "managerInstanceId": i.ManagerInstanceID, "profile": i.Profile, "origin": i.Origin, "deviceId": i.DeviceID, "intentId": i.IntentID, "certificateHash": f.cert.CertificateHash(), "requestId": c.RequestID, "challenge": f.challenge.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.overviewAuthorityKey, message))})
	proof, err := enrollmentcrypto.VerifyActivation(raw, f.cert, f.challenge, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.snapshot, err = f.store.Activate(context.Background(), c, proof)
	if err != nil {
		t.Fatal(err)
	}
}
func (f *overviewAuthorityFixture) revoke(t *testing.T) {
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
func (f *overviewAuthorityFixture) listen(t *testing.T, wrap func(http.Handler) http.Handler) (*enrollmenttransport.Ingress, *httptest.Server, *http.Client) {
	t.Helper()
	s := httptest.NewUnstartedServer(nil)
	origin := "https://" + s.Listener.Addr().String()
	if f.config.Binding.Profile == "http-test" {
		origin = "http://" + s.Listener.Addr().String()
	}
	h, err := enrollmenttransport.New(f.store, f.issuer.IssuerDER(), origin)
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

func (f *overviewAuthorityFixture) material(t *testing.T, origin string) (Material, string) {
	t.Helper()
	dir := t.TempDir()
	c := Config{SchemaVersion: ConfigVersion, Profile: f.config.Binding.Profile, ManagerOrigin: origin, AgentID: f.snapshot.Approval.DeviceID, CertificateFile: filepath.Join(dir, "client.pem"), PrivateKeyFile: filepath.Join(dir, "client.key"), StateDirectory: filepath.Join(dir, "state"), InsecureHTTPAcknowledged: f.config.Binding.Profile == "http-test"}
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cert.DER()})
	if c.Profile == "tls" {
		cp = append(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.IssuerDER()})...)
		c.ServerCAFile = filepath.Join(dir, "ca.pem")
		if os.WriteFile(c.ServerCAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw}), 0600) != nil {
			t.Fatal("public fixture CA")
		}
	}
	key, err := x509.MarshalPKCS8PrivateKey(f.overviewAuthorityKey)
	if err != nil {
		t.Fatal("fixture key encoding")
	}
	if os.WriteFile(c.CertificateFile, cp, 0600) != nil || os.WriteFile(c.PrivateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600) != nil {
		t.Fatal("fixture material")
	}
	clear(key)
	m, err := loadConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	return prepareEndpointHandoff(t, m)
}

func TestOverviewSenderRealAuthorityExactRetryRestartDisableAndRevocation(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		t.Run(profile, func(t *testing.T) {
			f := newOverviewAuthorityFixture(t, profile, enrollmentcrypto.CollectionProfileComplete, true)
			if err := f.store.InitializeOverview(context.Background()); err != nil {
				t.Fatal(err)
			}
			var lose atomic.Bool
			lose.Store(true)
			var requests atomic.Int32
			var mu sync.Mutex
			var appendBodies [][]byte
			_, server, _ := f.listen(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.URL.Path == overviewwire.PathPrefix+"append" {
						raw, err := io.ReadAll(io.LimitReader(r.Body, overviewwire.MaxBodyBytes+1))
						if err != nil {
							t.Error("fixture read")
							w.WriteHeader(500)
							return
						}
						r.Body = io.NopCloser(bytes.NewReader(raw))
						message, err := overviewwire.DecodeMessage("append", raw)
						if err != nil {
							t.Error("fixture message")
							w.WriteHeader(500)
							return
						}
						if message.Section == "processes" && message.Chunk.Ordinal == 0 {
							mu.Lock()
							appendBodies = append(appendBodies, bytes.Clone(raw))
							mu.Unlock()
							if lose.CompareAndSwap(true, false) {
								rec := httptest.NewRecorder()
								next.ServeHTTP(rec, r)
								if rec.Code != 200 {
									t.Error("fixture initial commit failed")
								}
								w.WriteHeader(503)
								return
							}
						}
					}
					next.ServeHTTP(w, r)
				})
			})
			m, path := f.material(t, server.URL)
			unchanged := overviewFileBytes(t, overviewExistingPaths(m))
			if out, err := configureCompleteOverview(path, "enable", true, overviewTestIdentity); err != nil || !out.Enabled {
				t.Fatal("explicit consent", err)
			}
			clock := &inventoryClock{}
			clock.set(time.Now().UTC())
			var captures atomic.Int32
			collect := func(ctx context.Context, id string, at time.Time) (completeoverview.Snapshot, error) {
				captures.Add(1)
				return syntheticOverview(ctx, id, at, 513, 300)
			}
			sender, err := openOverviewSenderWithSource(m, clock.now, collect)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { sender.Close() })
			report, err := burstOverview(sender)
			if !errors.Is(err, ErrOverviewTransport) || report.Processes.Status != "pending_retained" || captures.Load() != 1 {
				t.Fatal("uncertain commit not retained", err)
			}
			before, err := f.store.OverviewView(context.Background(), m.config.AgentID, time.Now().UTC())
			if err != nil || before.Processes.Complete != nil || before.Volumes.Complete == nil {
				t.Fatal("partial process promotion or sibling failure", err)
			}
			sender = reopenOverview(t, sender)
			report, err = burstOverview(sender)
			if err != nil || report.Processes.Status != "acknowledged" || captures.Load() != 1 {
				t.Fatal("restart did not drain exact pending generation", err)
			}
			mu.Lock()
			same := len(appendBodies) == 2 && bytes.Equal(appendBodies[0], appendBodies[1])
			mu.Unlock()
			if !same {
				t.Fatal("restart changed committed append bytes")
			}
			complete, err := f.store.OverviewView(context.Background(), m.config.AgentID, time.Now().UTC())
			if err != nil || complete.Processes.Complete == nil || complete.Volumes.Complete == nil {
				t.Fatal("missing complete sections", err)
			}
			if !complete.Volumes.Complete.CompletedAt.Equal(before.Volumes.Complete.CompletedAt) {
				t.Fatal("process retry refreshed sibling")
			}
			for _, section := range []string{"processes", "volumes"} {
				req := overviewledger.PageRequest{Section: section, Limit: 73}
				seen := 0
				for {
					page, err := f.store.OverviewPage(context.Background(), m.config.AgentID, req, time.Now().UTC())
					if err != nil {
						t.Fatal(err)
					}
					if !page.Manifest.CollectedAt.Equal(clock.now()) {
						t.Fatal("server replaced original source age")
					}
					for _, row := range page.Items {
						seen++
						if section == "processes" && (row.Process == nil || row.Process.PID != uint32(seen)) {
							t.Fatal("process page prefix/duplicate")
						}
					}
					if page.Exhausted {
						break
					}
					if page.NextCursor == "" {
						t.Fatal("missing continuation")
					}
					req.Cursor = page.NextCursor
				}
				want := 513
				if section == "volumes" {
					want = 300
				}
				if seen != want {
					t.Fatal("full generation count mismatch")
				}
			}
			sender.Close()
			if _, err = configureCompleteOverview(path, "disable", false, overviewTestIdentity); err != nil {
				t.Fatal(err)
			}
			count := requests.Load()
			off, err := openOverviewSenderWithSource(m, clock.now, collect)
			if err != nil || off != nil || requests.Load() != count {
				t.Fatal("disabled source/network construction", err)
			}
			if _, err = configureCompleteOverview(path, "enable", true, overviewTestIdentity); err != nil {
				t.Fatal(err)
			}
			sender, err = openOverviewSenderWithSource(m, clock.now, collect)
			if err != nil {
				t.Fatal(err)
			}
			// Re-submit a correctly framed, freshly authenticated exact previously
			// accepted append after revocation. No clock skew or source recapture is
			// involved in the denial.
			f.revoke(t)
			mu.Lock()
			replay := bytes.Clone(appendBodies[0])
			mu.Unlock()
			var request *http.Request
			if profile == "http-test" {
				request, err = overviewwire.NewSignedRequest(context.Background(), server.URL, m.certificate, "append", 1, time.Now().UTC(), replay)
			} else {
				request, err = http.NewRequest(http.MethodPost, server.URL+overviewwire.PathPrefix+"append", bytes.NewReader(replay))
				if err == nil {
					request.Header.Set("Content-Type", "application/json")
				}
			}
			if err != nil {
				t.Fatal("revoked request fixture")
			}
			response, err := sender.processes.client.Do(request)
			if err != nil {
				t.Fatal("revoked transport", err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatal("revoked exact append accepted")
			}

			if _, err = f.store.OverviewView(context.Background(), m.config.AgentID, time.Now().UTC()); !errors.Is(err, enrollmentstate.ErrState) {
				t.Fatal("revoked rows readable", err)
			}
			overviewFilesUnchanged(t, unchanged)
		})
	}
}
