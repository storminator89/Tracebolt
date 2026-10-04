package enrollmentcrypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"localrmm/internal/keyvalidation"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func ValidID(v, prefix string) bool {
	if len(v) != len(prefix)+32 || !strings.HasPrefix(v, prefix) {
		return false
	}
	return validHex(v[len(prefix):], 32)
}
func validHex(v string, n int) bool {
	if len(v) != n || strings.Trim(v, "0") == "" {
		return false
	}
	raw, e := hex.DecodeString(v)
	return e == nil && hex.EncodeToString(raw) == v
}
func ValidHash(v string) bool { return validHex(v, 64) }
func canonicalOrigin(raw, profile string) bool {
	scheme := "https"
	portDefault := "443"
	if profile == "http-test" {
		scheme = "http"
		portDefault = "80"
	} else if profile != "tls" {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 512 || u.Scheme != scheme || u.User != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || raw != scheme+"://"+u.Host || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(raw, "\\%\r\n\t ") {
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
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || p == portDefault {
			return false
		}
		authority = net.JoinHostPort(host, p)
	}
	return authority == u.Host
}
func secretBytes(value string) ([]byte, error) {
	b, e := base64.RawURLEncoding.Strict().DecodeString(value)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != value {
		return nil, ErrContract
	}
	return b, nil
}

// InvitationHash hashes high-entropy32-byte invitation material. It neither
// generates a secret nor determines whether an invitation is authorized.
func InvitationHash(secret string) ([32]byte, error) {
	var zero [32]byte
	b, e := secretBytes(secret)
	if e != nil {
		return zero, e
	}
	defer clear(b)
	return sha256.Sum256(append([]byte("tracebolt.invitation.v2\x00"), b...)), nil
}
func validContext(c ChallengeContext, now time.Time) bool {
	if now.Unix() <= 0 || now.Unix() > 253402300499 || !ValidID(c.ManagerInstanceID, "manager_") || !ValidID(c.InvitationID, "invite_") || !ValidID(c.ClaimID, "claim_") || !ValidCollectionProfile(c.CollectionProfile) || !canonicalOrigin(c.Origin, c.Profile) || c.ExpiresAt <= now.Unix() || c.ExpiresAt > now.Unix()+300 {
		return false
	}
	b, e := secretBytes(c.Challenge)
	clear(b)
	return e == nil
}
func transcript(domain string, fields ...string) []byte {
	var b bytes.Buffer
	for _, field := range append([]string{domain}, fields...) {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(field)))
		b.WriteString(field)
	}
	return b.Bytes()
}
func hash(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func decodeBase64(value string, limit int) ([]byte, error) {
	if len(value) > base64.RawStdEncoding.EncodedLen(limit) {
		return nil, ErrContract
	}
	b, e := base64.RawStdEncoding.Strict().DecodeString(value)
	if e != nil || len(b) == 0 || len(b) > limit || base64.RawStdEncoding.EncodeToString(b) != value {
		return nil, ErrContract
	}
	return b, nil
}
func strictObject(raw []byte, out any, fields ...string) error {
	if len(raw) == 0 || len(raw) > MaxClaimBytes || !utf8.Valid(raw) {
		return ErrContract
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return ErrContract
	}
	seen := map[string]bool{}
	for d.More() {
		t, e = d.Token()
		key, ok := t.(string)
		if e != nil || !ok || !allowed[key] || seen[key] || strings.ContainsRune(key, utf8.RuneError) {
			return ErrContract
		}
		seen[key] = true
		v, e := d.Token()
		s, ok := v.(string)
		if e != nil || !ok || strings.ContainsRune(s, utf8.RuneError) {
			return ErrContract
		}
	}
	if _, e = d.Token(); e != nil {
		return ErrContract
	}
	if _, e = d.Token(); e != io.EOF || len(seen) != len(allowed) {
		return ErrContract
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return ErrContract
	}
	return nil
}

type claimInput struct {
	SchemaVersion     string `json:"schemaVersion"`
	ManagerInstanceID string `json:"managerInstanceId"`
	Profile           string `json:"profile"`
	Origin            string `json:"origin"`
	CollectionProfile string `json:"collectionProfile"`
	InvitationID      string `json:"invitationId"`
	ClaimID           string `json:"claimId"`
	RequestID         string `json:"requestId"`
	Challenge         string `json:"challenge"`
	InvitationSecret  string `json:"invitationSecret"`
	CSR               string `json:"csr"`
	Proof             string `json:"proof"`
}

func (claimInput) MarshalJSON() ([]byte, error) { return []byte(`{"secretRedacted":true}`), nil }
func (claimInput) String() string               { return "enrollment claim input (secret redacted)" }
func (claimInput) GoString() string             { return "enrollment claim input (secret redacted)" }
func parseCSR(raw []byte) (ed25519.PublicKey, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxCSRBytes {
		return nil, nil, ErrContract
	}
	csr, e := x509.ParseCertificateRequest(raw)
	if e != nil || csr.SignatureAlgorithm != x509.PureEd25519 || csr.CheckSignature() != nil {
		return nil, nil, ErrProof
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok || !keyvalidation.Ed25519(pub) {
		return nil, nil, ErrProof
	}
	der, e := x509.MarshalPKIXPublicKey(pub)
	if e != nil {
		return nil, nil, ErrProof
	}
	return bytes.Clone(pub), der, nil
}
func claimData(c ChallengeContext, requestID string, csr []byte, secret string) (ClaimMetadata, [32]byte, []byte, []byte, error) {
	var zero [32]byte
	if !ValidID(requestID, "request_") {
		return ClaimMetadata{}, zero, nil, nil, ErrContract
	}
	_, key, e := parseCSR(csr)
	if e != nil {
		return ClaimMetadata{}, zero, nil, nil, e
	}
	verifier, e := InvitationHash(secret)
	if e != nil {
		return ClaimMetadata{}, zero, nil, nil, e
	}
	m := ClaimMetadata{ManagerInstanceID: c.ManagerInstanceID, Profile: c.Profile, Origin: c.Origin, CollectionProfile: c.CollectionProfile, InvitationID: c.InvitationID, ClaimID: c.ClaimID, RequestID: requestID, KeyFingerprint: hash(key), CSRHash: hash(csr), ExpiresAt: c.ExpiresAt}
	base := []string{m.ManagerInstanceID, m.Profile, m.Origin, m.CollectionProfile, m.InvitationID, m.ClaimID, m.RequestID, m.KeyFingerprint, m.CSRHash, hex.EncodeToString(verifier[:])}
	m.ClaimHash = hash(transcript("Tracebolt enrollment semantic claim v2", base...))
	m.ComparisonCode = hash(transcript("Tracebolt enrollment comparison v2", m.ManagerInstanceID, m.InvitationID, m.ClaimID, m.KeyFingerprint))[:32]
	message := transcript("Tracebolt enrollment claim possession v2", append(base, c.Challenge, strconv.FormatInt(c.ExpiresAt, 10))...)
	return m, verifier, key, message, nil
}

// ClaimSigningMessage returns context-bound bytes for the endpoint to sign. It
// does not sign, grant approval, or return cryptographically verified evidence.
func ClaimSigningMessage(c ChallengeContext, requestID string, csr []byte, secret string, now time.Time) ([]byte, error) {
	if !validContext(c, now) {
		return nil, ErrContract
	}
	_, _, _, message, e := claimData(c, requestID, csr, secret)
	return message, e
}
func VerifyClaim(raw []byte, c ChallengeContext, now time.Time) (VerifiedClaim, error) {
	var out VerifiedClaim
	if !validContext(c, now) {
		return out, ErrContract
	}
	var in claimInput
	if strictObject(raw, &in, "schemaVersion", "managerInstanceId", "profile", "origin", "collectionProfile", "invitationId", "claimId", "requestId", "challenge", "invitationSecret", "csr", "proof") != nil {
		return out, ErrContract
	}
	if in.SchemaVersion != ClaimVersion || in.ManagerInstanceID != c.ManagerInstanceID || in.Profile != c.Profile || in.Origin != c.Origin || in.CollectionProfile != c.CollectionProfile || in.InvitationID != c.InvitationID || in.ClaimID != c.ClaimID || in.Challenge != c.Challenge {
		return out, ErrProof
	}
	csr, e := decodeBase64(in.CSR, MaxCSRBytes)
	if e != nil {
		return out, e
	}
	signature, e := decodeBase64(in.Proof, ed25519.SignatureSize)
	if e != nil || len(signature) != ed25519.SignatureSize {
		return out, ErrProof
	}
	metadata, verifier, key, message, e := claimData(c, in.RequestID, csr, in.InvitationSecret)
	if e != nil {
		return out, e
	}
	pub, e := x509.ParsePKIXPublicKey(key)
	if e != nil || !ed25519.Verify(pub.(ed25519.PublicKey), message, signature) {
		return out, ErrProof
	}
	return VerifiedClaim{seal: true, metadata: metadata, invitationHash: verifier, publicKeyDER: key}, nil
}
