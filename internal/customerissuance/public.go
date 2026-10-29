package customerissuance

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	"localrmm/internal/customerclaim"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

// Version 2 is the unexposed source projection with the public routing ID.
// Older fixture bytes lack that ID and are intentionally not accepted.
const PublicVersion = "tracebolt.customer-windows-public-intent.v2"
const maxPublicBytes = 4096

// PublicIntent deliberately omits the review actor, customer revision,
// operation, CSR and key bytes. IntentDigest binds the complete internal
// intent but cannot be independently recomputed from this projection.
// IntentID is a public routing identifier; the unchanged proof transcript binds
// the full internal IntentDigest rather than this field separately. The server
// must match both ID and digest against committed state. The leaf authenticates
// neither ID nor digest. An authenticated manager/lifecycle response must bind
// the entire projection. Neither this projection nor its digest proves
// persistence or approval.
type PublicIntent struct {
	Version            string `json:"version"`
	IntentID           string `json:"intentId"`
	IntentDigest       string `json:"intentDigest"`
	TemplateVersion    string `json:"templateVersion"`
	TransportProfile   string `json:"transportProfile"`
	CollectionProfile  string `json:"collectionProfile"`
	ManagerID          string `json:"managerId"`
	CustomerID         string `json:"customerId"`
	InstallerProfileID string `json:"installerProfileId"`
	ClaimID            string `json:"claimId"`
	DeviceID           string `json:"deviceId"`
	KeyFingerprint     string `json:"keyFingerprint"`
	IssuerFingerprint  string `json:"issuerFingerprint"`
	Origin             string `json:"origin"`
	AgentOrigin        string `json:"agentOrigin"`
	SerialHex          string `json:"serialHex"`
	NotBefore          int64  `json:"notBefore"`
	NotAfter           int64  `json:"notAfter"`
	DeadlineAt         int64  `json:"deadlineAt"`
}

// ProjectPublic takes a validated internal intent. The caller must separately
// verify protected persistence and live approval before publishing anything.
func ProjectPublic(i Intent) (PublicIntent, error) {
	digest, err := Digest(i)
	if err != nil {
		return PublicIntent{}, err
	}
	p := i.Approval.Candidate.Pending
	out := PublicIntent{Version: PublicVersion, IntentID: i.IntentID, IntentDigest: digest, TemplateVersion: i.TemplateVersion, TransportProfile: i.TransportProfile, CollectionProfile: i.CollectionProfile, ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, DeviceID: i.Approval.Candidate.DeviceID, KeyFingerprint: p.KeyFingerprint, IssuerFingerprint: p.IssuerFingerprint, Origin: p.Origin, AgentOrigin: p.AgentOrigin, SerialHex: i.SerialHex, NotBefore: i.NotBefore, NotAfter: i.NotAfter, DeadlineAt: p.DeadlineAt}
	if !ValidPublic(out) {
		return PublicIntent{}, ErrInvalid
	}
	return out, nil
}

// ValidPublic applies the same canonical HTTPS origin and identifier policy
// as customer claims. It does not authenticate provenance or bind a device.
func ValidPublic(p PublicIntent) bool {
	ctx := customerclaim.Context{ManagerID: p.ManagerID, CustomerID: p.CustomerID, InstallerProfileID: p.InstallerProfileID, ClaimID: p.ClaimID, Origin: p.Origin, AgentOrigin: p.AgentOrigin, IssuerFingerprint: p.IssuerFingerprint, Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), ExpiresAt: 2}
	return p.Version == PublicVersion && enrollmentcrypto.ValidID(p.IntentID, "intent_") && p.TemplateVersion == TemplateVersion && p.TransportProfile == "tls" && p.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory && enrollmentcrypto.ValidHash(p.IntentDigest) && enrollmentcrypto.ValidHash(p.KeyFingerprint) && enrollmentcrypto.ValidID(p.DeviceID, "agent_") && validSerial(p.SerialHex) && p.NotBefore > 0 && p.NotBefore < p.DeadlineAt && p.DeadlineAt <= maxTimestamp && p.NotAfter > p.NotBefore && p.NotAfter <= maxTimestamp && p.NotAfter-p.NotBefore <= int64(MaxLifetime/time.Second) && customerclaim.ValidChallengeContext(ctx, time.Unix(1, 0))
}

func CanonicalPublic(p PublicIntent) ([]byte, error) {
	if !ValidPublic(p) {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > maxPublicBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

func ParsePublic(raw []byte) (PublicIntent, error) {
	var p PublicIntent
	if len(raw) == 0 || len(raw) > maxPublicBytes || json.Unmarshal(raw, &p) != nil {
		return PublicIntent{}, ErrInvalid
	}
	canonical, err := CanonicalPublic(p)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PublicIntent{}, ErrInvalid
	}
	return p, nil
}

// LocalPublicBinding must come from the endpoint's independently authenticated,
// protected original profile and its own stored claim/key, never from the same
// unauthenticated response. PublicKeyDER is the local Ed25519 public key, not a
// private key. The caller must authenticate the live manager and separately
// enforce profile/claim lifecycle, trust, revocation and local consent.
type LocalPublicBinding struct {
	ManagerID, CustomerID, InstallerProfileID, ClaimID string
	IssuerFingerprint, Origin, AgentOrigin             string
	DeadlineAt                                         int64
	PublicKeyDER                                       []byte
}

// MatchLocalPublic checks the exact local binding and the original deadline.
// DeviceID, serial and validity are manager-selected, not locally preapproved.
// VerifyPublicLeaf can separately validate the fixed leaf against this projection
// and explicit trusted issuer material. No acceptance, issuance, activation or
// start authority follows from this match or that validation.
func MatchLocalPublic(p PublicIntent, local LocalPublicBinding, now time.Time) error {
	if !ValidPublic(p) || local.DeadlineAt != p.DeadlineAt || now.IsZero() || now.Unix() < p.NotBefore || now.Unix() >= p.NotAfter || now.Unix() >= p.DeadlineAt || p.ManagerID != local.ManagerID || p.CustomerID != local.CustomerID || p.InstallerProfileID != local.InstallerProfileID || p.ClaimID != local.ClaimID || p.IssuerFingerprint != local.IssuerFingerprint || p.Origin != local.Origin || p.AgentOrigin != local.AgentOrigin {
		return ErrInvalid
	}
	key, err := x509.ParsePKIXPublicKey(local.PublicKeyDER)
	if err != nil {
		return ErrInvalid
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(pub) {
		return ErrInvalid
	}
	canonical, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil || !bytes.Equal(canonical, local.PublicKeyDER) {
		return ErrInvalid
	}
	h := sha256.Sum256(canonical)
	if hex.EncodeToString(h[:]) != p.KeyFingerprint {
		return ErrInvalid
	}
	return nil
}
