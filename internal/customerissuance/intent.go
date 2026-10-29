// Package customerissuance defines a fixed, public customer Windows issuance
// intent. It never signs, delivers, activates or grants collection authority.
// Callers must establish protected storage and hold current reviewed authority
// before persisting an intent, signing, delivering or accepting observations.
package customerissuance

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"localrmm/internal/customerapproval"
	"localrmm/internal/customerapprovalstore"
	"localrmm/internal/enrollmentauthority"
	"localrmm/internal/enrollmentcrypto"
)

const Version = "tracebolt.customer-windows-issuance-intent.v1"
const TemplateVersion = "tracebolt.customer-windows-client.v1"
const MaxLifetime = 30 * 24 * time.Hour
const maxTimestamp = int64(253402300499)
const maxIntentBytes = 16 << 10

var ErrInvalid = errors.New("customer issuance intent is invalid")

// Intent is public and immutable once durably admitted. Approval is included
// in full so its actor, manager digest, customer revision and original pending
// claim/key/CSR/issuer/origin bindings enter the domain-separated digest. It
// contains no raw CSR, private key, invitation or consent grant.
type Intent struct {
	Version           string                       `json:"version"`
	TemplateVersion   string                       `json:"templateVersion"`
	TransportProfile  string                       `json:"transportProfile"`
	CollectionProfile string                       `json:"collectionProfile"`
	Approval          customerapprovalstore.Record `json:"approval"`
	IntentID          string                       `json:"intentId"`
	SerialHex         string                       `json:"serialHex"`
	NotBefore         int64                        `json:"notBefore"`
	NotAfter          int64                        `json:"notAfter"`
}

func validActor(a customerapprovalstore.Actor) bool {
	return a.Mode == "shared" && a.ID == "" || a.Mode == "named" && enrollmentcrypto.ValidID(a.ID, "operator_")
}

func validSerial(s string) bool {
	if len(s) != 32 || s == "00000000000000000000000000000000" {
		return false
	}
	b, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(b) == s
}

// Valid checks only the fixed public structure and original binding. The
// approval record is NOT proof of current approval or issuer authority, and
// neither a well-formed value nor its digest permits signing.
func Valid(i Intent) bool {
	a := i.Approval
	return i.Version == Version && i.TemplateVersion == TemplateVersion && i.TransportProfile == "tls" &&
		i.CollectionProfile == enrollmentcrypto.CollectionProfileWindowsInventory &&
		a.Version == "tracebolt.customer-approval-record.v1" && validActor(a.Actor) && customerapproval.Valid(a.Candidate) &&
		enrollmentcrypto.ValidID(i.IntentID, "intent_") && validSerial(i.SerialHex) &&
		i.NotBefore >= a.Candidate.ConfirmedAt && i.NotBefore > 0 && i.NotBefore < a.Candidate.Pending.DeadlineAt &&
		i.NotAfter > i.NotBefore && i.NotAfter <= maxTimestamp && i.NotAfter-i.NotBefore <= int64(MaxLifetime/time.Second)
}

// Build fixes the intent ID, positive 128-bit serial and absolute validity.
// These inputs must be chosen by trusted manager code, not by a device. A
// caller must hold the real current approval/review/issuer authority and persist
// exactly this intent in the authoritative enrollment transaction; Build alone
// neither validates nor creates approval, consent or signing authority.
func Build(a customerapprovalstore.Record, intentID, serialHex string, now time.Time, lifetime time.Duration) (Intent, error) {
	if now.IsZero() || lifetime <= 0 || lifetime > MaxLifetime || lifetime%time.Second != 0 || now.Unix() <= 0 || now.Unix() > maxTimestamp-int64(lifetime/time.Second) {
		return Intent{}, ErrInvalid
	}
	i := Intent{Version: Version, TemplateVersion: TemplateVersion, TransportProfile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Approval: a, IntentID: intentID, SerialHex: serialHex, NotBefore: now.Unix(), NotAfter: now.Unix() + int64(lifetime/time.Second)}
	i.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(a.Candidate.Pending.PublicKeyDER)
	if !Valid(i) {
		return Intent{}, ErrInvalid
	}
	return i, nil
}

// Current rejects expiry, time before the fixed intent and the original pending
// deadline. This check does not validate a live issuer, session, revocation,
// approved enrollment state, or evidence that this exact intent was committed.
func Current(i Intent, now time.Time) bool {
	return Valid(i) && !now.IsZero() && now.Unix() >= i.NotBefore && now.Unix() < i.NotAfter && now.Unix() < i.Approval.Candidate.Pending.DeadlineAt
}

// ValidateIssuer checks the exact public client-auth issuer/root policy and
// fixed validity window, with the fingerprint bound in the original claim.
// It does not check current manager configuration, revocation, ownership of a
// private key, trusted input provenance or permission to sign.
func ValidateIssuer(i Intent, issuerDER, rootDER []byte, now time.Time) error {
	if !Current(i, now) || enrollmentauthority.ValidatePublicAuthority(issuerDER, rootDER, i.Approval.Candidate.Pending.IssuerFingerprint, now) != nil {
		return ErrInvalid
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil || time.Unix(i.NotBefore, 0).Before(issuer.NotBefore) || time.Unix(i.NotAfter, 0).After(issuer.NotAfter) {
		return ErrInvalid
	}
	return nil
}

// Canonical serializes public data in fixed shape; no identity or provenance
// authentication is inferred from these bytes.
func Canonical(i Intent) ([]byte, error) {
	if !Valid(i) {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(i)
	if err != nil || len(raw) > maxIntentBytes {
		return nil, ErrInvalid
	}
	return raw, nil
}

// Parse accepts exactly canonical JSON: duplicate/unknown fields, reordered
// fields and alternate encodings fail. It does not establish current authority.
func Parse(raw []byte) (Intent, error) {
	var i Intent
	if len(raw) == 0 || len(raw) > maxIntentBytes || json.Unmarshal(raw, &i) != nil {
		return Intent{}, ErrInvalid
	}
	canonical, err := Canonical(i)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Intent{}, ErrInvalid
	}
	return i, nil
}

// Digest is a domain-separated immutable comparison for this version. It is
// not a signature, approval, proof of persistence, or permission to sign.
func Digest(i Intent) (string, error) {
	raw, err := Canonical(i)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, _ = h.Write([]byte("tracebolt.customer-windows-issuance-intent.v1\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
