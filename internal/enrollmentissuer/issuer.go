// Package enrollmentissuer signs only the fixed enrollment leaf contract with
// preprovided, dedicated intermediate material. It performs no filesystem or
// network operations and never generates keys or chooses issuance intent fields.
// Possession of an Issuer or its result is not device approval or delivery
// authority. The caller must durably authorize and record the intent before
// signing, and persist the verified result before any credential delivery.
package enrollmentissuer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"time"

	"localrmm/internal/enrollmentcrypto"
)

var (
	ErrConfiguration = errors.New("enrollment issuer configuration is invalid")
	ErrIntent        = errors.New("enrollment issuance intent is invalid for this issuer")
	ErrSigning       = errors.New("enrollment certificate signing failed")
)

// Issuer is an opaque, immutable signing handle. Copies share private, read-only
// material rather than exposing or copying the private key. Both pointer and
// value formatting/serialization are redacted. There is no key export method.
type Issuer struct{ state *issuerState }

type issuerState struct {
	issuer      *x509.Certificate
	root        *x509.Certificate
	key         ed25519.PrivateKey
	fingerprint string
}

func (Issuer) String() string                 { return "enrollmentissuer.Issuer{material:redacted}" }
func (Issuer) GoString() string               { return "enrollmentissuer.Issuer{material:redacted}" }
func (i Issuer) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, i.String()) }
func (Issuer) MarshalJSON() ([]byte, error)   { return []byte(`{"materialRedacted":true}`), nil }
func (i Issuer) MarshalText() ([]byte, error) { return []byte(i.String()), nil }
func (i Issuer) LogValue() slog.Value         { return slog.StringValue(i.String()) }

// New accepts exactly one client-only, pathLen0 Ed25519 intermediate directly
// signed by the explicit public root. expectedIssuerFingerprint is the exact
// lowercase SHA256 of issuerDER from trusted instance configuration, not a claim.
// No root private key is accepted. Callers own protected loading and custody.
//
// signer must contain a concrete, preprovided ed25519.PrivateKey; a private copy
// is retained. Arbitrary crypto.Signer implementations (including remote/HSM
// providers) are deliberately unsupported until they have a separately reviewed
// deterministic issuance/reconciliation contract. This restriction plus the
// fixed template makes exact intent retries byte-identical on reconstruction.
func New(issuerDER, rootDER []byte, signer crypto.Signer, expectedIssuerFingerprint string, now time.Time) (*Issuer, error) {
	key, ok := signer.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize || !enrollmentcrypto.ValidHash(expectedIssuerFingerprint) || !validTime(now) {
		return nil, ErrConfiguration
	}
	issuer, err := parsePublicCertificate(issuerDER)
	if err != nil {
		return nil, ErrConfiguration
	}
	root, err := parsePublicCertificate(rootDER)
	if err != nil || fingerprint(issuer.Raw) != expectedIssuerFingerprint || verifyAuthority(issuer, root, now) != nil {
		return nil, ErrConfiguration
	}
	privateCopy := ed25519.PrivateKey(bytes.Clone(key))
	public := privateCopy.Public().(ed25519.PublicKey)
	if !bytes.Equal(public, issuer.PublicKey.(ed25519.PublicKey)) {
		return nil, ErrConfiguration
	}
	// A malformed 64-byte Ed25519 private key can carry another key's public
	// suffix. Check actual possession too, with a fixed local domain-separated
	// message. Neither this proof nor any private material leaves the handle.
	proof := []byte("Tracebolt enrollment issuer material validation v2")
	if !ed25519.Verify(public, proof, ed25519.Sign(privateCopy, proof)) {
		return nil, ErrConfiguration
	}
	return &Issuer{state: &issuerState{issuer: issuer, root: root, key: privateCopy, fingerprint: expectedIssuerFingerprint}}, nil
}

// Fingerprint returns public issuer metadata, or an empty string for a zero or
// nil handle. It is not an authorization decision.
func (i *Issuer) Fingerprint() string {
	if i == nil || i.state == nil {
		return ""
	}
	return i.state.fingerprint
}

// IssuerDER returns a defensive copy of the public intermediate certificate.
func (i *Issuer) IssuerDER() []byte {
	if i == nil || i.state == nil {
		return nil
	}
	return bytes.Clone(i.state.issuer.Raw)
}

// RootDER returns a defensive copy of the explicitly supplied public root.
func (i *Issuer) RootDER() []byte {
	if i == nil || i.state == nil {
		return nil
	}
	return bytes.Clone(i.state.root.Raw)
}

// Sign validates a complete, already persisted intent and signs only its fixed
// client leaf. It copies no CSR field and chooses no serial, validity or identity.
// Repeated signing of the same valid intent produces the same DER, even after
// reconstructing the handle. There is no durable state or approval check here;
// the store must recheck authority when committing and delivering the result.
// Cancellation observed before return discards the local result. An in-progress
// standard-library signing operation cannot itself be interrupted.
func (i *Issuer) Sign(ctx context.Context, intent enrollmentcrypto.Intent, now time.Time) (enrollmentcrypto.VerifiedCertificate, error) {
	var zero enrollmentcrypto.VerifiedCertificate
	if i == nil || i.state == nil || ctx == nil {
		return zero, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	s := i.state
	if !validTime(now) || enrollmentcrypto.ValidateIntent(intent) != nil || intent.IssuerFingerprint != s.fingerprint {
		return zero, ErrIntent
	}
	if verifyAuthority(s.issuer, s.root, now) != nil {
		return zero, ErrConfiguration
	}
	notBefore, notAfter := time.Unix(intent.NotBefore, 0).UTC(), time.Unix(intent.NotAfter, 0).UTC()
	if now.Before(notBefore) || !now.Before(notAfter) || notBefore.Before(s.issuer.NotBefore) || notAfter.After(s.issuer.NotAfter) {
		return zero, ErrIntent
	}
	serial, ok := new(big.Int).SetString(intent.SerialHex, 16)
	if !ok || serial.Sign() <= 0 || serial.BitLen() > 128 {
		return zero, ErrIntent
	}
	publicDER, err := base64.RawStdEncoding.DecodeString(intent.PublicKeyDERBase64)
	if err != nil {
		return zero, ErrIntent
	}
	public, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		return zero, ErrIntent
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: intent.DeviceID},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    x509.PureEd25519,
		BasicConstraintsValid: true,
		IsCA:                  false,
		MaxPathLen:            -1,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId:        bytes.Clone(s.issuer.SubjectKeyId),
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	// Ed25519 signing and the persisted positive serial need no entropy. This
	// reader makes accidental future randomized behavior fail closed.
	der, err := x509.CreateCertificate(noEntropy{}, template, s.issuer, public, s.key)
	if err != nil {
		return zero, ErrSigning
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	verified, err := enrollmentcrypto.VerifyIssued(der, s.issuer.Raw, intent, now)
	if err != nil {
		return zero, ErrSigning
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return verified, nil
}

type noEntropy struct{}

func (noEntropy) Read([]byte) (int, error) { return 0, ErrSigning }

func fingerprint(der []byte) string {
	hash := sha256.Sum256(der)
	return hex.EncodeToString(hash[:])
}

func validTime(now time.Time) bool { return now.Unix() > 0 && now.Unix() <= 253402300799 }
