package customerapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/customerpending"
	_ "modernc.org/sqlite"
)

type fixtureLease struct{}

func (fixtureLease) Check() error { return nil }
func (fixtureLease) Release()     {}

func fixture(t *testing.T) (customerpending.ReviewExpectation, customerpending.Record, Decision, time.Time) {
	t.Helper()
	now := time.Unix(1790000000, 0).UTC()
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err = customerpending.Initialize(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := customerpending.New(db)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	c := customerclaim.Context{ManagerID: "manager_" + strings.Repeat("1", 32), CustomerID: "customer_" + strings.Repeat("2", 32), InstallerProfileID: "profile_" + strings.Repeat("3", 32), Origin: "https://manager.example.test", AgentOrigin: "https://agent.example.test", IssuerFingerprint: strings.Repeat("a", 64), ClaimID: "claim_" + strings.Repeat("4", 32), Challenge: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)), ExpiresAt: now.Unix() + 60}
	request := "request_" + strings.Repeat("5", 32)
	msg, err := customerclaim.SigningMessage(c, request, csr, now)
	if err != nil {
		t.Fatal(err)
	}
	body, err := customerclaim.Encode(c, request, csr, ed25519.Sign(key, msg), now)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := customerclaim.Verify(body, c, now)
	if err != nil {
		t.Fatal(err)
	}
	acquire := func(context.Context, customerclaim.Metadata) (customerpending.AuthorityLease, error) {
		return fixtureLease{}, nil
	}
	record, err := store.Accept(ctx, proof, func() time.Time { return now }, acquire)
	if err != nil {
		t.Fatal(err)
	}
	e := customerpending.ReviewExpectation{ManagerID: record.ManagerID, CustomerID: record.CustomerID, InstallerProfileID: record.InstallerProfileID, ClaimID: record.ClaimID, ClaimHash: record.ClaimHash, KeyFingerprint: record.KeyFingerprint, ManagerDigest: strings.Repeat("b", 64), CustomerRevision: 3, DeadlineAt: record.DeadlineAt}
	allowReview := func(context.Context, customerclaim.Metadata, string, uint64) (customerpending.AuthorityLease, error) {
		return fixtureLease{}, nil
	}
	lease, err := store.AcquireReview(ctx, e, func() time.Time { return now }, allowReview)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	record, err = lease.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	d := Decision{OperationID: "request_" + strings.Repeat("8", 32), DeviceID: "agent_" + strings.Repeat("9", 32), Acknowledged: true, FingerprintCompared: true}
	return e, record, d, now
}

func TestCandidateBindsReviewedSnapshotAndReturnsDetachedData(t *testing.T) {
	e, p, d, now := fixture(t)
	c, err := Build(e, p, d, now)
	if err != nil || !Valid(c) {
		t.Fatal("candidate rejected", err)
	}
	if c.ManagerDigest != e.ManagerDigest || c.CustomerRevision != e.CustomerRevision || c.DeviceID != d.DeviceID || c.Pending.ClaimHash != p.ClaimHash || c.ConfirmedAt != now.Unix() {
		t.Fatal("binding changed")
	}
	original := bytes.Clone(c.Pending.PublicKeyDER)
	p.PublicKeyDER[0] ^= 1
	if !bytes.Equal(c.Pending.PublicKeyDER, original) {
		t.Fatal("mutable snapshot leaked")
	}
	raw, err := Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil || !Valid(parsed) {
		t.Fatal("canonical roundtrip", err)
	}
	digest, err := Digest(c)
	if err != nil || len(digest) != 64 {
		t.Fatal("digest", err)
	}
	parsed.DeviceID = "agent_" + strings.Repeat("a", 32)
	other, err := Digest(parsed)
	if err != nil || other == digest {
		t.Fatal("device not bound")
	}
}

func TestCandidateRejectsUnconfirmedOrChangedReview(t *testing.T) {
	e, p, d, now := fixture(t)
	for name, change := range map[string]func(*customerpending.ReviewExpectation, *customerpending.Record, *Decision){
		"unacknowledged": func(_ *customerpending.ReviewExpectation, _ *customerpending.Record, d *Decision) {
			d.Acknowledged = false
		},
		"comparison": func(_ *customerpending.ReviewExpectation, _ *customerpending.Record, d *Decision) {
			d.FingerprintCompared = false
		},
		"customer": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.CustomerID = "customer_" + strings.Repeat("9", 32)
		},
		"manager": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.ManagerID = "manager_" + strings.Repeat("9", 32)
		},
		"profile": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.InstallerProfileID = "profile_" + strings.Repeat("9", 32)
		},
		"claim": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.ClaimID = "claim_" + strings.Repeat("9", 32)
		},
		"hash": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.ClaimHash = strings.Repeat("f", 64)
		},
		"key": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.KeyFingerprint = strings.Repeat("f", 64)
		},
		"deadline": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) { e.DeadlineAt-- },
		"revision": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.CustomerRevision = 0
		},
		"digest": func(e *customerpending.ReviewExpectation, _ *customerpending.Record, _ *Decision) {
			e.ManagerDigest = ""
		},
		"device":    func(_ *customerpending.ReviewExpectation, _ *customerpending.Record, d *Decision) { d.DeviceID = "" },
		"operation": func(_ *customerpending.ReviewExpectation, _ *customerpending.Record, d *Decision) { d.OperationID = "" },
		"stored-key": func(_ *customerpending.ReviewExpectation, p *customerpending.Record, _ *Decision) {
			p.PublicKeyDER = bytes.Clone(p.PublicKeyDER)
			p.PublicKeyDER[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			ee, pp, dd := e, p, d
			change(&ee, &pp, &dd)
			if _, err := Build(ee, pp, dd, now); err == nil {
				t.Fatal("invalid candidate accepted")
			}
		})
	}
	if _, err := Build(e, p, d, time.Unix(p.DeadlineAt, 0)); err == nil {
		t.Fatal("expired review accepted")
	}
	if _, err := Build(e, p, d, now.Add(-time.Second)); err == nil {
		t.Fatal("review before claim accepted")
	}
}

func TestParseRejectsNoncanonicalOrInjectedData(t *testing.T) {
	e, p, d, now := fixture(t)
	c, err := Build(e, p, d, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Canonical(c)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("invalid fixture")
	}
	v["secret"] = "never accepted"
	extra, _ := json.Marshal(v)
	for name, b := range map[string][]byte{"unknown": extra, "duplicate": append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"deviceId":"`+d.DeviceID+`"}`)...), "whitespace": append([]byte(" "), raw...), "trailing": append(append([]byte(nil), raw...), []byte(` {}`)...), "oversize": bytes.Repeat([]byte(" "), maxCandidateBytes+1)} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(b); err == nil {
				t.Fatal("malformed candidate accepted")
			}
		})
	}
}
