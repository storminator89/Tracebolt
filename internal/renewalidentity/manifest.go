// Package renewalidentity defines the create-only, same-key identity manifest.
// It contains public material only. The protected storage owner atomically
// publishes the whole manifest after committed manager activation; original
// enrollment artifacts and local grants are never rewritten by renewal.
package renewalidentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"localrmm/internal/enrollmentcrypto"
	"math"
	"time"
)

const Version = "tracebolt.renewable-identity.v1"
const Policy = "same-key-v1"
const ManifestName = "renewal-manifest.json"
const LedgerName = "renewal-transaction.json"
const MaxBytes = 64 << 10

var ErrInvalid = errors.New("renewable identity manifest is unavailable or invalid")

// Manifest separates a never-changing enrollment identity and original scope
// anchor from the currently activated transport credential. AuthorityExpiresAt
// is the explicitly consented original identity horizon, never a sliding grant.
type Manifest struct {
	Version              string                  `json:"version"`
	ManagerInstanceID    string                  `json:"managerInstanceId"`
	EnrollmentOrigin     string                  `json:"enrollmentOrigin"`
	AgentOrigin          string                  `json:"agentOrigin"`
	CollectionProfile    string                  `json:"collectionProfile"`
	DeviceID             string                  `json:"deviceId"`
	IdentityGeneration   string                  `json:"identityGeneration"`
	KeyFingerprint       string                  `json:"keyFingerprint"`
	AnchorHash           string                  `json:"anchorHash"`
	IssuerFingerprint    string                  `json:"issuerFingerprint"`
	AuthorityExpiresAt   int64                   `json:"authorityExpiresAt"`
	CredentialGeneration uint64                  `json:"credentialGeneration"`
	Revision             uint64                  `json:"revision"`
	CertificateDER       []byte                  `json:"certificateDer"`
	AnchorIntent         enrollmentcrypto.Intent `json:"anchorIntent"`
	Intent               enrollmentcrypto.Intent `json:"intent"`
	LastServerNow        int64                   `json:"lastServerNow"`
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// Parse rejects unknown fields, nulls and duplicate keys, including nested
// intents. Size is bounded before JSON allocation; validation is separate.
func Parse(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) == 0 || len(raw) > MaxBytes || strictJSON(raw, &m) != nil {
		return Manifest{}, ErrInvalid
	}
	return m, nil
}

func strictJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return ErrInvalid
		}
		token, e := d.Token()
		if e != nil || token == nil {
			return ErrInvalid
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return ErrInvalid
				}
				seen[s] = true
				if walk(depth+1) != nil {
					return ErrInvalid
				}
			}
			t, e := d.Token()
			if e != nil || t != json.Delim('}') {
				return ErrInvalid
			}
		case json.Delim('['):
			return ErrInvalid
		}
		return nil
	}
	if walk(0) != nil {
		return ErrInvalid
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	return nil
}

// Validate authenticates both original and current fixed issuance descriptions.
// The original anchor is checked at its issuance time only as historical
// identity evidence. Only the current credential grants live transport validity.
func (m Manifest) Validate(anchor, issuer *x509.Certificate, managerOrigin, collectionProfile, deviceID string, now time.Time) (*x509.Certificate, error) {
	fail := func() (*x509.Certificate, error) { return nil, ErrInvalid }
	if anchor == nil || issuer == nil || m.Version != Version || m.AgentOrigin != managerOrigin || m.CollectionProfile != collectionProfile || m.DeviceID != deviceID || !enrollmentcrypto.ValidID(m.IdentityGeneration, "identity_") || m.CredentialGeneration == 0 || m.CredentialGeneration > math.MaxInt64 || m.Revision == 0 || m.Revision > math.MaxInt64 || m.LastServerNow <= 0 || now.Unix() < m.LastServerNow || m.AuthorityExpiresAt <= now.Unix() || m.AuthorityExpiresAt > issuer.NotAfter.Unix() || m.AnchorHash != digest(anchor.Raw) || m.IssuerFingerprint != digest(issuer.Raw) || m.KeyFingerprint != digest(anchor.RawSubjectPublicKeyInfo) {
		return fail()
	}
	a, i := m.AnchorIntent, m.Intent
	identity, identityErr := enrollmentcrypto.RenewalIdentityGeneration(a)
	if identityErr != nil || identity != m.IdentityGeneration {
		return fail()
	}
	if a.Profile != "tls" || i.Profile != "tls" || m.ManagerInstanceID != a.ManagerInstanceID || m.EnrollmentOrigin != a.Origin || m.CollectionProfile != a.CollectionProfile || m.DeviceID != a.DeviceID || m.KeyFingerprint != a.KeyFingerprint || m.IssuerFingerprint != a.IssuerFingerprint || i.ManagerInstanceID != a.ManagerInstanceID || i.Origin != a.Origin || i.CollectionProfile != a.CollectionProfile || i.InvitationID != a.InvitationID || i.ClaimID != a.ClaimID || i.DeviceID != a.DeviceID || i.KeyFingerprint != a.KeyFingerprint || i.PublicKeyDERBase64 != a.PublicKeyDERBase64 || i.CSRHash != a.CSRHash || i.ClaimHash != a.ClaimHash || i.IssuerFingerprint != a.IssuerFingerprint || i.KeyGeneration != a.KeyGeneration || i.NotAfter > m.AuthorityExpiresAt {
		return fail()
	}
	if _, e := enrollmentcrypto.VerifyIssued(anchor.Raw, issuer.Raw, a, time.Unix(a.NotBefore, 0)); e != nil {
		return fail()
	}
	if _, e := enrollmentcrypto.VerifyIssued(m.CertificateDER, issuer.Raw, i, now); e != nil {
		return fail()
	}
	current, e := x509.ParseCertificate(m.CertificateDER)
	if e != nil || !bytes.Equal(current.RawSubjectPublicKeyInfo, anchor.RawSubjectPublicKeyInfo) {
		return fail()
	}
	if m.CredentialGeneration == 1 && (i != a || !bytes.Equal(m.CertificateDER, anchor.Raw)) {
		return fail()
	}
	if m.CredentialGeneration > 1 && (i.IntentID == a.IntentID || i.SerialHex == a.SerialHex || i.NotAfter <= a.NotAfter) {
		return fail()
	}
	return current, nil
}
