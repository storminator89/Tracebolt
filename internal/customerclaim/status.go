package customerclaim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
)

// StatusVersion is for key-bound status reads only, not credential issuance or
// activation. A caller must separately consume a status-purpose challenge and
// authorize the current retained claim under its own live authority lease.
const StatusVersion = "tracebolt.customer-windows-status.v1"

type statusBody struct {
	SchemaVersion  string `json:"schemaVersion"`
	ClaimHash      string `json:"claimHash"`
	KeyFingerprint string `json:"keyFingerprint"`
	RequestID      string `json:"requestId"`
	Challenge      string `json:"challenge"`
	Proof          string `json:"proof"`
}

// VerifiedStatus proves key possession for one challenge. It is not a read
// lease, admission, approval, credential request or replay fence.
type VerifiedStatus struct {
	valid     bool
	requestID string
	expiresAt int64
	metadata  Metadata
}

func (v VerifiedStatus) Valid() bool       { return v.valid }
func (v VerifiedStatus) RequestID() string { return v.requestID }
func (v VerifiedStatus) ExpiresAt() int64  { return v.expiresAt }

// Metadata is a value copy of the original public claim binding, to compare
// against current durable state before answering; it grants no authority.
func (v VerifiedStatus) Metadata() Metadata         { return v.metadata }
func (VerifiedStatus) String() string               { return "customerclaim.VerifiedStatus{proof:redacted}" }
func (VerifiedStatus) GoString() string             { return "customerclaim.VerifiedStatus{proof:redacted}" }
func (VerifiedStatus) MarshalJSON() ([]byte, error) { return []byte(`{"proofRedacted":true}`), nil }

func statusMessage(c Context, m Metadata, publicKeyDER []byte, requestID string, now time.Time) ([]byte, error) {
	if !validContext(c, now) || !enrollmentcrypto.ValidID(requestID, "request_") || !ValidateStoredMetadata(m, publicKeyDER) ||
		c.ManagerID != m.ManagerID || c.CustomerID != m.CustomerID || c.InstallerProfileID != m.InstallerProfileID ||
		c.Origin != m.Origin || c.AgentOrigin != m.AgentOrigin || c.IssuerFingerprint != m.IssuerFingerprint || c.ClaimID != m.ClaimID {
		return nil, ErrContract
	}
	return transcript("Tracebolt customer Windows status possession v1", m.ClaimHash, m.KeyFingerprint, requestID, c.Challenge, strconv.FormatInt(c.ExpiresAt, 10)), nil
}

// StatusSigningMessage constructs status-specific bytes for the locally held
// key. On the server, metadata and publicKeyDER must come from trusted retained
// state, never from an untrusted request. The challenge must be purpose-bound.
func StatusSigningMessage(c Context, m Metadata, publicKeyDER []byte, requestID string, now time.Time) ([]byte, error) {
	return statusMessage(c, m, publicKeyDER, requestID, now)
}

// EncodeStatus uses an externally generated signature; it does not accept a
// private key and creates neither a challenge nor authority to read a status.
func EncodeStatus(c Context, m Metadata, publicKeyDER []byte, requestID string, signature []byte, now time.Time) ([]byte, error) {
	msg, err := statusMessage(c, m, publicKeyDER, requestID, now)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return nil, ErrProof
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || len(signature) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, signature) {
		return nil, ErrProof
	}
	return json.Marshal(statusBody{StatusVersion, m.ClaimHash, m.KeyFingerprint, requestID, c.Challenge, base64.RawStdEncoding.EncodeToString(signature)})
}

func strictStatus(raw []byte, out *statusBody) error {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
		return ErrContract
	}
	allowed := map[string]bool{"schemaVersion": true, "claimHash": true, "keyFingerprint": true, "requestId": true, "challenge": true, "proof": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('{') {
		return ErrContract
	}
	seen := map[string]bool{}
	for d.More() {
		tok, err = d.Token()
		key, ok := tok.(string)
		if err != nil || !ok || !allowed[key] || seen[key] || strings.ContainsRune(key, utf8.RuneError) {
			return ErrContract
		}
		seen[key] = true
		tok, err = d.Token()
		value, ok := tok.(string)
		if err != nil || !ok || strings.ContainsRune(value, utf8.RuneError) {
			return ErrContract
		}
	}
	tok, err = d.Token()
	if err != nil || tok != json.Delim('}') || len(seen) != len(allowed) {
		return ErrContract
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrContract
	}
	if json.Unmarshal(raw, out) != nil {
		return ErrContract
	}
	return nil
}

// VerifyStatus checks only a status proof against server-owned context and the
// retained key. VerifiedStatus does not expire automatically; consumers must
// recheck time, challenge consumption and retained identity at the read edge.
func VerifyStatus(raw []byte, c Context, m Metadata, publicKeyDER []byte, now time.Time) (VerifiedStatus, error) {
	var in statusBody
	if strictStatus(raw, &in) != nil {
		return VerifiedStatus{}, ErrContract
	}
	if in.SchemaVersion != StatusVersion || in.ClaimHash != m.ClaimHash || in.KeyFingerprint != m.KeyFingerprint || in.Challenge != c.Challenge {
		return VerifiedStatus{}, ErrProof
	}
	msg, err := statusMessage(c, m, publicKeyDER, in.RequestID, now)
	if err != nil {
		return VerifiedStatus{}, err
	}
	sig, err := decode(in.Proof, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return VerifiedStatus{}, ErrProof
	}
	parsed, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		return VerifiedStatus{}, ErrProof
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || !ed25519.Verify(pub, msg, sig) {
		return VerifiedStatus{}, ErrProof
	}
	// The earlier claim challenge is not part of durable identity; status
	// expiry is exposed separately and must be checked at the response edge.
	m.ExpiresAt = 0
	return VerifiedStatus{valid: true, requestID: in.RequestID, expiresAt: c.ExpiresAt, metadata: m}, nil
}
