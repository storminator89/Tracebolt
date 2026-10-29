// Package customerclaim verifies a fresh customer-bound Windows device request.
// It does not create challenges, persist state, grant enrollment, issue a
// certificate, authorize collection, or provide a network endpoint. Callers
// must obtain the challenge context from a trusted, bounded server-side source
// and consume it exactly once before accepting a verified proof.
package customerclaim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/keyvalidation"
)

const Version = "tracebolt.customer-windows-claim.v1"
const MaxBytes = 16 << 10
const MaxCSRBytes = 8 << 10
const MaxChallengeLifetime = 60 * time.Second

var ErrContract = errors.New("customer device request is invalid")
var ErrProof = errors.New("customer device proof is invalid")

// Context must come from the manager's own stored challenge, never from the
// untrusted request body. InstallerProfileID identifies an immutable profile;
// mutable customer catalog revisions belong to the separate operator review.
// Challenge freshness alone is not a replay fence.
type Context struct {
	ManagerID          string
	CustomerID         string
	InstallerProfileID string
	Origin             string
	AgentOrigin        string
	IssuerFingerprint  string
	ClaimID            string
	Challenge          string
	ExpiresAt          int64
}

type Metadata struct {
	ManagerID, CustomerID, InstallerProfileID, Origin, AgentOrigin, IssuerFingerprint string
	ClaimID, RequestID, KeyFingerprint, CSRHash, ClaimHash, ComparisonCode            string
	ExpiresAt                                                                         int64
}

// Verified is an opaque validation result, not admission or an approval token.
type Verified struct {
	valid        bool
	metadata     Metadata
	publicKeyDER []byte
}

func (v Verified) Valid() bool                { return v.valid }
func (v Verified) Metadata() Metadata         { return v.metadata }
func (v Verified) PublicKeyDER() []byte       { return bytes.Clone(v.publicKeyDER) }
func (Verified) String() string               { return "customerclaim.Verified{proof:redacted}" }
func (Verified) GoString() string             { return "customerclaim.Verified{proof:redacted}" }
func (Verified) MarshalJSON() ([]byte, error) { return []byte(`{"proofRedacted":true}`), nil }

type body struct {
	SchemaVersion      string `json:"schemaVersion"`
	ManagerID          string `json:"managerInstanceId"`
	CustomerID         string `json:"customerId"`
	InstallerProfileID string `json:"installerProfileId"`
	Profile            string `json:"profile"`
	Origin             string `json:"origin"`
	AgentOrigin        string `json:"agentOrigin"`
	CollectionProfile  string `json:"collectionProfile"`
	IssuerFingerprint  string `json:"issuerFingerprint"`
	ClaimID            string `json:"claimId"`
	RequestID          string `json:"requestId"`
	Challenge          string `json:"challenge"`
	CSR                string `json:"csr"`
	Proof              string `json:"proof"`
}

var bodyFields = []string{"schemaVersion", "managerInstanceId", "customerId", "installerProfileId", "profile", "origin", "agentOrigin", "collectionProfile", "issuerFingerprint", "claimId", "requestId", "challenge", "csr", "proof"}

// canonicalTLSOrigin enforces the existing enrollment-origin shape, without
// allowing an input URL to carry credentials, secrets, query or path data.
func canonicalTLSOrigin(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 512 || u.Scheme != "https" || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || raw != "https://"+u.Host || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(raw, "\\%\r\n\t ") {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return false
				}
			}
		}
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if p := u.Port(); p != "" {
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || p == "443" {
			return false
		}
		authority = net.JoinHostPort(host, p)
	}
	return authority == u.Host
}

func validContext(c Context, now time.Time) bool {
	if now.Unix() <= 0 || now.Unix() > 253402300499 || !enrollmentcrypto.ValidID(c.ManagerID, "manager_") || !enrollmentcrypto.ValidID(c.CustomerID, "customer_") || !enrollmentcrypto.ValidID(c.InstallerProfileID, "profile_") || !canonicalTLSOrigin(c.Origin) || !canonicalTLSOrigin(c.AgentOrigin) || !enrollmentcrypto.ValidHash(c.IssuerFingerprint) || !enrollmentcrypto.ValidID(c.ClaimID, "claim_") || c.ExpiresAt <= now.Unix() || c.ExpiresAt > now.Unix()+int64(MaxChallengeLifetime/time.Second) {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(c.Challenge)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == c.Challenge
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func transcript(domain string, fields ...string) []byte {
	var out bytes.Buffer
	for _, value := range append([]string{domain}, fields...) {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(value)))
		out.WriteString(value)
	}
	return out.Bytes()
}
func decode(value string, limit int) ([]byte, error) {
	if len(value) > base64.RawStdEncoding.EncodedLen(limit) {
		return nil, ErrContract
	}
	b, err := base64.RawStdEncoding.Strict().DecodeString(value)
	if err != nil || len(b) == 0 || len(b) > limit || base64.RawStdEncoding.EncodeToString(b) != value {
		return nil, ErrContract
	}
	return b, nil
}

func metadata(c Context, requestID string, csr []byte) (Metadata, ed25519.PublicKey, []byte, error) {
	if !enrollmentcrypto.ValidID(requestID, "request_") || len(csr) == 0 || len(csr) > MaxCSRBytes {
		return Metadata{}, nil, nil, ErrContract
	}
	req, err := x509.ParseCertificateRequest(csr)
	if err != nil || req.SignatureAlgorithm != x509.PureEd25519 || req.CheckSignature() != nil {
		return Metadata{}, nil, nil, ErrProof
	}
	key, ok := req.PublicKey.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(key) {
		return Metadata{}, nil, nil, ErrProof
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return Metadata{}, nil, nil, ErrProof
	}
	m := Metadata{ManagerID: c.ManagerID, CustomerID: c.CustomerID, InstallerProfileID: c.InstallerProfileID, Origin: c.Origin, AgentOrigin: c.AgentOrigin, IssuerFingerprint: c.IssuerFingerprint, ClaimID: c.ClaimID, RequestID: requestID, KeyFingerprint: digest(der), CSRHash: digest(csr), ExpiresAt: c.ExpiresAt}
	m.ClaimHash, m.ComparisonCode = metadataDigests(m)
	return m, bytes.Clone(key), der, nil
}

// SigningMessage returns public, domain-separated bytes to sign with the CSR's
// device key. The caller retains responsibility for protecting that key.
func SigningMessage(c Context, requestID string, csr []byte, now time.Time) ([]byte, error) {
	if !validContext(c, now) {
		return nil, ErrContract
	}
	m, _, _, err := metadata(c, requestID, csr)
	if err != nil {
		return nil, err
	}
	return transcript("Tracebolt customer Windows possession v1", m.ClaimHash, c.Challenge, strconv.FormatInt(c.ExpiresAt, 10)), nil
}

// Encode constructs a public request from an externally generated signature.
// It does not accept the device private key and does not confer any authority.
func Encode(c Context, requestID string, csr, signature []byte, now time.Time) ([]byte, error) {
	message, err := SigningMessage(c, requestID, csr, now)
	if err != nil {
		return nil, err
	}
	_, key, _, err := metadata(c, requestID, csr)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, message, signature) {
		return nil, ErrProof
	}
	v := body{Version, c.ManagerID, c.CustomerID, c.InstallerProfileID, "tls", c.Origin, c.AgentOrigin, enrollmentcrypto.CollectionProfileWindowsInventory, c.IssuerFingerprint, c.ClaimID, requestID, c.Challenge, base64.RawStdEncoding.EncodeToString(csr), base64.RawStdEncoding.EncodeToString(signature)}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxBytes {
		return nil, ErrContract
	}
	return raw, nil
}

// Verify accepts only a fully specified public request and the trusted server
// challenge context. Verified proofs still require independent local scope and
// operator approval before any certificate, collection or identity activation.
func Verify(raw []byte, c Context, now time.Time) (Verified, error) {
	if !validContext(c, now) {
		return Verified{}, ErrContract
	}
	var v body
	if strictObject(raw, &v) != nil {
		return Verified{}, ErrContract
	}
	if v.SchemaVersion != Version || v.ManagerID != c.ManagerID || v.CustomerID != c.CustomerID || v.InstallerProfileID != c.InstallerProfileID || v.Profile != "tls" || v.Origin != c.Origin || v.AgentOrigin != c.AgentOrigin || v.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || v.IssuerFingerprint != c.IssuerFingerprint || v.ClaimID != c.ClaimID || v.Challenge != c.Challenge {
		return Verified{}, ErrProof
	}
	csr, err := decode(v.CSR, MaxCSRBytes)
	if err != nil {
		return Verified{}, err
	}
	sig, err := decode(v.Proof, ed25519.SignatureSize)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Verified{}, ErrProof
	}
	m, key, der, err := metadata(c, v.RequestID, csr)
	if err != nil {
		return Verified{}, err
	}
	message := transcript("Tracebolt customer Windows possession v1", m.ClaimHash, c.Challenge, strconv.FormatInt(c.ExpiresAt, 10))
	if !ed25519.Verify(key, message, sig) {
		return Verified{}, ErrProof
	}
	return Verified{valid: true, metadata: m, publicKeyDER: der}, nil
}

// Decode all fields as exact-case strings, rejecting duplicates, unknown fields,
// malformed UTF-8 and unpaired JSON surrogate escapes.
func strictObject(raw []byte, out *body) error {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) {
		return ErrContract
	}
	allowed := make(map[string]bool, len(bodyFields))
	for _, f := range bodyFields {
		allowed[f] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return ErrContract
	}
	seen := make(map[string]bool, len(bodyFields))
	for d.More() {
		t, err = d.Token()
		key, ok := t.(string)
		if err != nil || !ok || !allowed[key] || seen[key] || strings.ContainsRune(key, utf8.RuneError) {
			return ErrContract
		}
		seen[key] = true
		t, err = d.Token()
		value, ok := t.(string)
		if err != nil || !ok || strings.ContainsRune(value, utf8.RuneError) {
			return ErrContract
		}
	}
	t, err = d.Token()
	if err != nil || t != json.Delim('}') {
		return ErrContract
	}
	if _, err = d.Token(); err != io.EOF || len(seen) != len(allowed) {
		return ErrContract
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return ErrContract
	}
	return nil
}
