package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/enrollmentservice"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
)

// All material is generated only in memory for an isolated temporary database.
// These tests exercise application-service contracts, never a network endpoint.
type independentServiceFixture struct {
	now         atomic.Int64
	store       *enrollmentstore.Store
	path        string
	service     *enrollmentservice.Service
	issuer      *enrollmentissuer.Issuer
	key         ed25519.PrivateKey
	keyDER, csr []byte
	request     int
}

func independentServiceNew(t *testing.T, freshIssuer bool) *independentServiceFixture {
	t.Helper()
	return independentServiceNewBound(t, freshIssuer, "https://manager.example", "tls")
}

func independentServiceNewBound(t *testing.T, freshIssuer bool, origin, profile string) *independentServiceFixture {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("private enrollment SQLite adapter is Linux-only")
	}
	f := &independentServiceFixture{}
	f.now.Store(independentEnrollmentNow)
	now := f.clock()
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral root generation failed")
	}
	rootSKI := sha256.Sum256(rootPub)
	root := &x509.Certificate{SerialNumber: big.NewInt(701), Subject: pkix.Name{CommonName: "Disposable service root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rootSKI[:20]}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootPub, rootKey)
	if err != nil {
		t.Fatal("ephemeral root certificate failed")
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal("ephemeral root parse failed")
	}
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral issuer generation failed")
	}
	issuerSKI := sha256.Sum256(issuerPub)
	before := now.Add(-time.Hour)
	if freshIssuer {
		before = now
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(702), Subject: pkix.Name{CommonName: "Disposable service intermediate"}, NotBefore: before, NotAfter: now.Add(60 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: issuerSKI[:20], AuthorityKeyId: root.SubjectKeyId}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, root, issuerPub, rootKey)
	if err != nil {
		t.Fatal("ephemeral intermediate certificate failed")
	}
	fingerprint := sha256.Sum256(issuerDER)
	f.issuer, err = enrollmentissuer.New(issuerDER, rootDER, issuerKey, hex.EncodeToString(fingerprint[:]), now)
	if err != nil {
		t.Fatal("ephemeral dedicated issuer rejected")
	}
	cfg := independentEnrollmentConfig()
	cfg.Binding.Origin, cfg.Binding.Profile = origin, profile
	cfg.RecordLimit, cfg.InvitationLimit, cfg.PendingLimit = 25, 25, 25
	cfg.Binding.IssuerFingerprint = f.issuer.Fingerprint()
	f.path = filepath.Join(t.TempDir(), "private", "enrollment.sqlite")
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, issuerDER)
	f.service, err = enrollmentservice.New(f.store, f.issuer, f.clock)
	if err != nil {
		t.Fatal("service fixture rejected")
	}
	_, f.key, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("ephemeral client generation failed")
	}
	f.keyDER, err = x509.MarshalPKIXPublicKey(f.key.Public())
	if err != nil {
		t.Fatal("ephemeral client encoding failed")
	}
	f.csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, f.key)
	if err != nil {
		t.Fatal("ephemeral client CSR failed")
	}
	return f
}
func (f *independentServiceFixture) clock() time.Time { return time.Unix(f.now.Load(), 0).UTC() }
func (f *independentServiceFixture) nextRequest() string {
	f.request++
	return independentEnrollmentID("request", 20000+f.request)
}
func (f *independentServiceFixture) challenge(t *testing.T, s enrollmentstate.Snapshot, purpose string) enrollmentservice.Challenge {
	t.Helper()
	claimID := s.Claim.ClaimID
	if claimID == "" {
		claimID = independentEnrollmentID("claim", 20001)
	}
	c, err := f.service.Challenge("192.0.2.40", s.InvitationID, claimID, purpose)
	if err != nil {
		t.Fatal("fixture challenge failed")
	}
	return c
}
func (f *independentServiceFixture) statusBody(t *testing.T, c enrollmentservice.Challenge, purpose string) []byte {
	t.Helper()
	request := f.nextRequest()
	m, err := enrollmentcrypto.StatusSigningMessage(c.Context, purpose, request, f.keyDER, f.clock())
	if err != nil {
		t.Fatal("ordinary fixture status signing failed")
	}
	fingerprint := sha256.Sum256(f.keyDER)
	raw, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.StatusVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": c.Context.InvitationID, "claimId": c.Context.ClaimID, "keyFingerprint": hex.EncodeToString(fingerprint[:]), "requestId": request, "purpose": purpose, "challenge": c.Context.Challenge, "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, m))})
	if err != nil {
		t.Fatal("fixture status encoding failed")
	}
	return raw
}
func (f *independentServiceFixture) pending(t *testing.T) enrollmentstate.Snapshot {
	t.Helper()
	created, err := f.service.CreateInvitation(context.Background(), f.nextRequest(), "linux")
	if err != nil {
		t.Fatal("fixture invitation failed")
	}
	c := f.challenge(t, created.Snapshot(), "claim")
	request := f.nextRequest()
	m, err := enrollmentcrypto.ClaimSigningMessage(c.Context, request, f.csr, created.Secret(), f.clock())
	if err != nil {
		t.Fatal("ordinary fixture claim signing failed")
	}
	raw, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": c.Context.ManagerInstanceID, "profile": c.Context.Profile, "origin": c.Context.Origin, "collectionProfile": c.Context.CollectionProfile, "invitationId": c.Context.InvitationID, "claimId": c.Context.ClaimID, "requestId": request, "challenge": c.Context.Challenge, "invitationSecret": created.Secret(), "csr": base64.RawStdEncoding.EncodeToString(f.csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, m))})
	if err != nil {
		t.Fatal("fixture claim encoding failed")
	}
	s, err := f.service.Claim(context.Background(), c.Context.Challenge, raw)
	if err != nil {
		t.Fatal("ordinary authorized claim failed")
	}
	return s
}
func (f *independentServiceFixture) approved(t *testing.T) enrollmentstate.Snapshot {
	t.Helper()
	s := f.pending(t)
	s, err := f.service.Approve(context.Background(), s.InvitationID, f.nextRequest(), s.Claim.KeyFingerprint, s.Revision)
	if err != nil {
		t.Fatal("fixture approval failed")
	}
	return s
}
func (f *independentServiceFixture) status(t *testing.T, s enrollmentstate.Snapshot) (enrollmentstate.Snapshot, error) {
	t.Helper()
	c := f.challenge(t, s, enrollmentcrypto.PurposeStatus)
	return f.service.Status(context.Background(), c.Context.Challenge, f.statusBody(t, c, enrollmentcrypto.PurposeStatus))
}

func TestIndependentEnrollmentServiceInvitationRedaction(t *testing.T) {
	f := independentServiceNew(t, false)
	created, err := f.service.CreateInvitation(context.Background(), f.nextRequest(), "linux")
	if err != nil {
		t.Fatal("invitation failed")
	}
	for _, value := range []any{created, &created} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%f"} {
			if strings.Contains(fmt.Sprintf(verb, value), created.Secret()) {
				t.Errorf("invitation secret exposed by format %s", verb)
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || bytes.Contains(raw, []byte(created.Secret())) {
			t.Error("invitation JSON did not redact secret")
		}
	}
}

func TestIndependentEnrollmentServiceFreshIssuer(t *testing.T) {
	f := independentServiceNew(t, true)
	s := f.approved(t)
	issued, err := f.status(t, s)
	if err != nil {
		t.Fatal("valid fresh issuer must not persist an intent before its own NotBefore")
	}
	if issued.State != enrollmentstate.Issued || issued.Intent.NotBefore < f.clock().Unix() {
		t.Fatal("fresh issuer validity boundary was not respected")
	}
}

func TestIndependentEnrollmentServiceChallengeBounds(t *testing.T) {
	t.Run("peer limit and trusted clock", func(t *testing.T) {
		f := independentServiceNew(t, false)
		id, claim := independentEnrollmentID("invite", 30001), independentEnrollmentID("claim", 30001)
		for n := 0; n < 30; n++ {
			if _, err := f.service.Challenge("192.0.2.8", id, claim, "status"); err != nil {
				t.Fatal("premature peer limit")
			}
		}
		if _, err := f.service.Challenge("::ffff:192.0.2.8", id, claim, "status"); !errors.Is(err, enrollmentservice.ErrBusy) {
			t.Fatal("IPv4-mapped alias bypassed peer limit")
		}
		f.now.Add(60)
		c, err := f.service.Challenge("192.0.2.8", id, claim, "status")
		if err != nil || !c.ServerNow.Equal(f.clock()) || c.Context.ExpiresAt != f.clock().Add(time.Minute).Unix() {
			t.Fatal("challenge did not reset against trusted server clock")
		}
		f.now.Add(-1)
		if _, err := f.service.Status(context.Background(), c.Context.Challenge, []byte("{}")); !errors.Is(err, enrollmentservice.ErrChallenge) {
			t.Fatal("clock rollback extended challenge")
		}
	})
	t.Run("global cap", func(t *testing.T) {
		f := independentServiceNew(t, false)
		id, claim := independentEnrollmentID("invite", 30002), independentEnrollmentID("claim", 30002)
		for n := 0; n < 120; n++ {
			c, err := f.service.Challenge(fmt.Sprintf("198.51.100.%d", n/30+1), id, claim, "status")
			if err != nil {
				t.Fatal("premature global challenge limit")
			}
			// Consumption frees map capacity, but must not reset the admission rate.
			_, _ = f.service.Status(context.Background(), c.Context.Challenge, []byte("{}"))
		}
		if _, err := f.service.Challenge("203.0.113.9", id, claim, "status"); !errors.Is(err, enrollmentservice.ErrBusy) {
			t.Fatal("unbounded challenge admission")
		}
		f.now.Add(60)
		if _, err := f.service.Challenge("203.0.113.9", id, claim, "status"); err != nil {
			t.Fatal("expired capacity was not reclaimed")
		}
	})
}

func TestIndependentEnrollmentServicePurposeAndOneUse(t *testing.T) {
	f := independentServiceNew(t, false)
	s := f.pending(t)
	c := f.challenge(t, s, "status")
	raw := f.statusBody(t, c, "status")
	if _, err := f.service.Credential(context.Background(), c.Context.Challenge, raw); !errors.Is(err, enrollmentservice.ErrChallenge) {
		t.Fatal("status challenge authorized credential path")
	}
	if _, err := f.service.Status(context.Background(), c.Context.Challenge, raw); !errors.Is(err, enrollmentservice.ErrChallenge) {
		t.Fatal("wrong-purpose attempt did not consume challenge")
	}
	c = f.challenge(t, s, "status")
	raw = f.statusBody(t, c, "credential")
	if _, err := f.service.Status(context.Background(), c.Context.Challenge, raw); !errors.Is(err, enrollmentcrypto.ErrProof) {
		t.Fatal("credential-purpose proof was not rejected before state lookup")
	}
	got, err := f.status(t, s)
	if err != nil || got.State != enrollmentstate.ClaimedPending {
		t.Fatal("ordinary pending proof failed or bypassed approval")
	}
	c = f.challenge(t, s, "status")
	raw = f.statusBody(t, c, "status")
	f.now.Add(60)
	if _, err := f.service.Status(context.Background(), c.Context.Challenge, raw); !errors.Is(err, enrollmentservice.ErrChallenge) {
		t.Fatal("expired challenge accepted")
	}
}

type independentServiceInterruptedSigner struct {
	*enrollmentissuer.Issuer
	certificate enrollmentcrypto.VerifiedCertificate
	entered     chan struct{}
	release     chan struct{}
}

func (s *independentServiceInterruptedSigner) Sign(ctx context.Context, i enrollmentcrypto.Intent, now time.Time) (enrollmentcrypto.VerifiedCertificate, error) {
	c, err := s.Issuer.Sign(ctx, i, now)
	if err != nil {
		return c, err
	}
	s.certificate = c
	if s.entered != nil {
		close(s.entered)
		<-s.release
		return c, nil
	}
	return enrollmentcrypto.VerifiedCertificate{}, errors.New("simulated local result loss before commit")
}

func TestIndependentEnrollmentServiceRestartReconcilesIdenticalCredential(t *testing.T) {
	f := independentServiceNew(t, false)
	s := f.approved(t)
	interrupted := &independentServiceInterruptedSigner{Issuer: f.issuer}
	var err error
	f.service, err = enrollmentservice.New(f.store, interrupted, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.status(t, s); err == nil {
		t.Fatal("simulated interrupted result was not stopped")
	}
	stranded, err := f.store.Get(context.Background(), s.InvitationID)
	if err != nil || stranded.State != enrollmentstate.IssuanceIntent {
		t.Fatal("signing began before durable intent or committed lost result")
	}
	old := f.challenge(t, stranded, "status")
	oldRaw := f.statusBody(t, old, "status")
	cfg := f.store.Config()
	if err := f.store.Close(); err != nil {
		t.Fatal("closing disposable durable store failed")
	}
	f.store = independentEnrollmentStoreOpen(t, f.path, cfg, f.issuer.IssuerDER())
	f.service, err = enrollmentservice.New(f.store, f.issuer, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.service.Status(context.Background(), old.Context.Challenge, oldRaw); !errors.Is(err, enrollmentservice.ErrChallenge) {
		t.Fatal("restart retained process-local challenge")
	}
	issued, err := f.status(t, stranded)
	if err != nil || issued.State != enrollmentstate.Issued || issued.Intent != stranded.Intent {
		t.Fatal("reconciliation changed intent or did not issue")
	}
	c := f.challenge(t, issued, "credential")
	der, err := f.service.Credential(context.Background(), c.Context.Challenge, f.statusBody(t, c, "credential"))
	if err != nil || !bytes.Equal(der, interrupted.certificate.DER()) {
		t.Fatal("reconciliation minted a different certificate")
	}
	repeated, err := f.status(t, issued)
	if err != nil || repeated != issued {
		t.Fatal("issued status retry changed immutable lifecycle")
	}
}

func TestIndependentEnrollmentServiceRevocationWinsSignerRace(t *testing.T) {
	f := independentServiceNew(t, false)
	s := f.approved(t)
	blocked := &independentServiceInterruptedSigner{Issuer: f.issuer, entered: make(chan struct{}), release: make(chan struct{})}
	var err error
	f.service, err = enrollmentservice.New(f.store, blocked, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	c := f.challenge(t, s, "status")
	raw := f.statusBody(t, c, "status")
	result := make(chan error, 1)
	go func() { _, err := f.service.Status(context.Background(), c.Context.Challenge, raw); result <- err }()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("signer did not start")
	}
	release := true
	defer func() {
		if release {
			close(blocked.release)
		}
	}()
	during, err := f.store.Get(context.Background(), s.InvitationID)
	if err != nil || during.State != enrollmentstate.IssuanceIntent {
		t.Fatal("signer started before durable intent")
	}
	revoked, err := f.service.Terminate(context.Background(), during.InvitationID, f.nextRequest(), during.Revision, enrollmentstate.Revoked)
	if err != nil {
		t.Fatal("revocation failed during signing")
	}
	close(blocked.release)
	release = false
	if err := <-result; err == nil {
		t.Fatal("signing result overrode revocation")
	}
	got, err := f.status(t, revoked)
	if err != nil || got != revoked {
		t.Fatal("bound key could not inspect terminal outcome")
	}
	c = f.challenge(t, revoked, "credential")
	if der, err := f.service.Credential(context.Background(), c.Context.Challenge, f.statusBody(t, c, "credential")); err == nil || len(der) != 0 {
		t.Fatal("revoked signing race delivered credential")
	}
}

func TestIndependentEnrollmentServiceCopiedHandleConsumesProofOnce(t *testing.T) {
	f := independentServiceNew(t, false)
	s := f.pending(t)
	c := f.challenge(t, s, "status")
	raw := f.statusBody(t, c, "status")
	copied := *f.service
	var successes, busy, consumed atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := copied.Status(context.Background(), c.Context.Challenge, raw)
			if err == nil {
				if got != s {
					t.Error("status read changed lifecycle")
				}
				successes.Add(1)
			} else if errors.Is(err, enrollmentservice.ErrChallenge) {
				consumed.Add(1)
			} else if errors.Is(err, enrollmentservice.ErrBusy) {
				busy.Add(1)
			} else {
				t.Error("unexpected concurrent status error")
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 || successes.Load()+busy.Load()+consumed.Load() != 12 {
		t.Fatal("concurrent copied handles consumed one challenge more than once or lost an outcome")
	}
	if _, err := copied.Status(context.Background(), c.Context.Challenge, raw); !errors.Is(err, enrollmentservice.ErrChallenge) {
		t.Fatal("sequential replay was not rejected after concurrent consumption")
	}
}

func TestIndependentEnrollmentServiceRejectsUnmeasuredRetentionLimit(t *testing.T) {
	f := independentServiceNew(t, false)
	cfg := f.store.Config()
	cfg.RecordLimit = enrollmentservice.MaxRecords + 1
	store := independentEnrollmentStoreOpen(t, filepath.Join(t.TempDir(), "private", "oversized.sqlite"), cfg, f.issuer.IssuerDER())
	if _, err := enrollmentservice.New(store, f.issuer, f.clock); !errors.Is(err, enrollmentservice.ErrConfiguration) {
		t.Fatal("service accepted retention beyond measured pilot cap")
	}
}

func TestIndependentEnrollmentServiceTwoProofSlotsBeforeStorage(t *testing.T) {
	f := independentServiceNew(t, false)
	var block atomic.Bool
	release := make(chan struct{})
	svc, err := enrollmentservice.New(f.store, f.issuer, func() time.Time {
		if block.Load() {
			<-release
		}
		return f.clock()
	})
	if err != nil {
		t.Fatal(err)
	}
	nonces := make([]string, 4)
	for n := range nonces {
		c, err := svc.Challenge("192.0.2.9", independentEnrollmentID("invite", 7001), independentEnrollmentID("claim", 7001), "status")
		if err != nil {
			t.Fatal(err)
		}
		nonces[n] = c.Context.Challenge
	}
	// A held trusted-clock read is before the first store read. At most two
	// operations may wait here; all others must finish promptly with ErrBusy.
	block.Store(true)
	type outcome struct {
		nonce string
		err   error
	}
	results := make(chan outcome, len(nonces))
	for _, nonce := range nonces {
		go func(nonce string) {
			_, err := svc.Status(context.Background(), nonce, []byte("{}"))
			results <- outcome{nonce, err}
		}(nonce)
	}
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	var busy []string
	for n := 0; n < 2; n++ {
		select {
		case r := <-results:
			if !errors.Is(r.err, enrollmentservice.ErrBusy) {
				t.Fatal("proof did work before admission gate")
			}
			busy = append(busy, r.nonce)
		case <-time.After(2 * time.Second):
			t.Fatal("excess proof queued instead of failing busy")
		}
	}
	block.Store(false)
	close(release)
	released = true
	for n := 0; n < 2; n++ {
		if r := <-results; !errors.Is(r.err, enrollmentstate.ErrNotFound) {
			t.Fatal("admitted request did not reach bounded store path")
		}
	}
	for _, nonce := range busy {
		if _, err := svc.Status(context.Background(), nonce, []byte("{}")); !errors.Is(err, enrollmentstate.ErrNotFound) {
			t.Fatal("busy rejection consumed nonce")
		}
		if _, err := svc.Status(context.Background(), nonce, []byte("{}")); !errors.Is(err, enrollmentservice.ErrChallenge) {
			t.Fatal("retry did not consume admitted nonce exactly once")
		}
	}
}
