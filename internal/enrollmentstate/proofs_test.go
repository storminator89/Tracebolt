package enrollmentstate

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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

type claimFixture struct {
	n         int
	challenge enrollmentcrypto.ChallengeContext
	secret    string
	key       ed25519.PrivateKey
	csr       []byte
	requestID string
}

func newClaimFixture(t *testing.T, n int) claimFixture {
	t.Helper()
	seed := sha256.Sum256([]byte(id("fixture", n)))
	key := ed25519.NewKeyFromSeed(seed[:])
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored client request"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	b := binding()
	return claimFixture{n: n, challenge: enrollmentcrypto.ChallengeContext{ManagerInstanceID: b.InstanceID, Profile: b.Profile, Origin: b.Origin, CollectionProfile: b.CollectionProfile, InvitationID: id("invite", n), ClaimID: id("claim", n), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(n)}, 32)), ExpiresAt: testNow + 120}, secret: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(n + 32)}, 32)), key: key, csr: csr, requestID: id("request", n*100+1)}
}

func (f claimFixture) proof(t *testing.T, now int64) enrollmentcrypto.VerifiedClaim {
	t.Helper()
	message, err := enrollmentcrypto.ClaimSigningMessage(f.challenge, f.requestID, f.csr, f.secret, time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]string{"schemaVersion": enrollmentcrypto.ClaimVersion, "managerInstanceId": f.challenge.ManagerInstanceID, "profile": f.challenge.Profile, "origin": f.challenge.Origin, "collectionProfile": f.challenge.CollectionProfile, "invitationId": f.challenge.InvitationID, "claimId": f.challenge.ClaimID, "requestId": f.requestID, "challenge": f.challenge.Challenge, "invitationSecret": f.secret, "csr": base64.RawStdEncoding.EncodeToString(f.csr), "proof": base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, message))})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := enrollmentcrypto.VerifyClaim(body, f.challenge, time.Unix(now, 0))
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func (f claimFixture) create(t *testing.T, e *Engine) Snapshot {
	t.Helper()
	h, err := enrollmentcrypto.InvitationHash(f.secret)
	if err != nil {
		t.Fatal(err)
	}
	s, err := e.CreateInvitation(context.Background(), CreateCommand{InvitationID: f.challenge.InvitationID, RequestID: id("request", f.n*100), InvitationHash: hex.EncodeToString(h[:]), Platform: "linux", Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f claimFixture) command(s Snapshot, now int64) ClaimCommand {
	return ClaimCommand{Control: Control{InvitationID: s.InvitationID, RequestID: f.requestID, ExpectedRevision: s.Revision, Now: now}, ClaimID: f.challenge.ClaimID}
}

func TestVerifiedClaimAndFreshChallengeRetry(t *testing.T) {
	c := DefaultConfig(binding())
	c.InvitationTTL = 10
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	f := newClaimFixture(t, 1)
	s := f.create(t, e)
	proof := f.proof(t, testNow+1)
	out, err := e.Claim(context.Background(), f.command(s, testNow+1), proof)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != ClaimedPending || out.Claim.KeyFingerprint != proof.KeyFingerprint() || out.DeadlineAt != testNow+1+MaxPendingTTL {
		t.Fatal("claim did not bind")
	}
	f.challenge.Challenge = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))
	f.challenge.ExpiresAt = testNow + 200
	fresh := f.proof(t, testNow+20)
	if fresh.ClaimHash() != proof.ClaimHash() {
		t.Fatal("ephemeral challenge changed semantic claim")
	}
	retry, err := e.Claim(context.Background(), f.command(s, testNow+20), fresh)
	if err != nil || retry != out {
		t.Fatalf("retry after original invitation expiry: %v", err)
	}
	if _, err := e.Claim(context.Background(), f.command(out, fresh.ExpiresAt()), fresh); !errors.Is(err, ErrProof) {
		t.Fatal(err)
	}
	unchanged(t, e, out)
	if _, err := e.Claim(context.Background(), f.command(out, out.DeadlineAt), fresh); !errors.Is(err, ErrExpired) {
		t.Fatal(err)
	}
	unchanged(t, e, out)
}

func TestVerifiedClaimConflictsAndContextIsolation(t *testing.T) {
	for _, scenario := range []string{"key", "csr", "request", "claim", "secret", "manager", "origin", "profile"} {
		t.Run(scenario, func(t *testing.T) {
			e := engine(t)
			f := newClaimFixture(t, 1)
			s := f.create(t, e)
			s, err := e.Claim(context.Background(), f.command(s, testNow+1), f.proof(t, testNow+1))
			if err != nil {
				t.Fatal(err)
			}
			g := f
			switch scenario {
			case "key":
				other := newClaimFixture(t, 2)
				g.key = other.key
				g.csr = other.csr
			case "csr":
				g.csr, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "changed"}}, g.key)
				if err != nil {
					t.Fatal(err)
				}
			case "request":
				g.requestID = id("request", 999)
			case "claim":
				g.challenge.ClaimID = id("claim", 999)
			case "secret":
				g.secret = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{88}, 32))
			case "manager":
				g.challenge.ManagerInstanceID = id("manager", 999)
			case "origin":
				g.challenge.Origin = "https://other.example"
			case "profile":
				g.challenge.Profile = "http-test"
				g.challenge.Origin = "http://manager.example"
			}
			if _, err := e.Claim(context.Background(), g.command(s, testNow+2), g.proof(t, testNow+2)); err == nil {
				t.Fatal("accepted changed claim")
			}
			unchanged(t, e, s)
		})
	}
}

func TestClaimPendingQuotaUniqueClaimAndCancellation(t *testing.T) {
	c := DefaultConfig(binding())
	c.PendingLimit = 1
	e, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	f1 := newClaimFixture(t, 1)
	s1 := f1.create(t, e)
	s1, err = e.Claim(context.Background(), f1.command(s1, testNow+1), f1.proof(t, testNow+1))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.Approve(context.Background(), ApproveCommand{Control: control(s1, 900), DeviceID: id("agent", 1), KeyFingerprint: s1.Claim.KeyFingerprint})
	if err != nil {
		t.Fatal(err)
	}
	f2 := newClaimFixture(t, 2)
	s2 := f2.create(t, e)
	if _, err := e.Claim(context.Background(), f2.command(s2, testNow+1), f2.proof(t, testNow+1)); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	unchanged(t, e, s2)
	e = engine(t)
	f1 = newClaimFixture(t, 1)
	s1 = f1.create(t, e)
	s1, err = e.Claim(context.Background(), f1.command(s1, testNow+1), f1.proof(t, testNow+1))
	if err != nil {
		t.Fatal(err)
	}
	f2 = newClaimFixture(t, 2)
	f2.challenge.ClaimID = f1.challenge.ClaimID
	s2 = f2.create(t, e)
	if _, err := e.Claim(context.Background(), f2.command(s2, testNow+1), f2.proof(t, testNow+1)); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	unchanged(t, e, s2)
	e = engine(t)
	f1 = newClaimFixture(t, 1)
	s1 = f1.create(t, e)
	if _, err := e.Claim(&cancelAtCommit{}, f1.command(s1, testNow+1), f1.proof(t, testNow+1)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	unchanged(t, e, s1)
}

func TestConcurrentVerifiedClaimsBindExactlyOneKey(t *testing.T) {
	e := engine(t)
	f := newClaimFixture(t, 1)
	s := f.create(t, e)
	g := f
	other := newClaimFixture(t, 2)
	g.key = other.key
	g.csr = other.csr
	proofs := []enrollmentcrypto.VerifiedClaim{f.proof(t, testNow+1), g.proof(t, testNow+1)}
	var wg sync.WaitGroup
	var successes [2]atomic.Int32
	var bad atomic.Int32
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := e.Claim(context.Background(), f.command(s, testNow+1), proofs[n%2])
			if err == nil {
				successes[n%2].Add(1)
			} else if !errors.Is(err, ErrConflict) {
				bad.Add(1)
			}
		}(n)
	}
	wg.Wait()
	if bad.Load() != 0 || !(successes[0].Load() == 16 && successes[1].Load() == 0 || successes[1].Load() == 16 && successes[0].Load() == 0) {
		t.Fatalf("claim winners %d/%d errors %d", successes[0].Load(), successes[1].Load(), bad.Load())
	}
	got, _ := e.Get(s.InvitationID)
	if got.Revision != 2 {
		t.Fatal("retry incremented revision")
	}
}
