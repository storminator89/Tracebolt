package enrollmentissuer

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"localrmm/internal/customerissuance"
)

// SignCustomer signs only the fixed customer Windows v3 client template using
// this handle's already validated, privately held Ed25519 issuer key. It reads
// no CSR, chooses no identity/serial/time, grants no enrollment authority, and
// cannot be used for arbitrary signing or a device-selected template. The caller
// must FIRST persist the exact intent in its authoritative enrollment transaction
// while holding the original approval/review/issuer/session guards, and must
// recheck those guards before storing and delivering the verified result.
// On cancellation the result is discarded; uncertainty never authorizes retry.
// This method is not connected to a manager route or a real device.
func (i *Issuer) SignCustomer(ctx context.Context, intent customerissuance.Intent, now time.Time) (customerissuance.VerifiedCertificate, error) {
	var zero customerissuance.VerifiedCertificate
	if i == nil || i.state == nil || ctx == nil {
		return zero, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	s := i.state
	// The intent contains only public data; detach its SPKI before use so the
	// generated certificate and verified digest use the same stable bytes.
	intent.Approval.Candidate.Pending.PublicKeyDER = bytes.Clone(intent.Approval.Candidate.Pending.PublicKeyDER)
	if !validTime(now) || !customerissuance.Current(intent, now) || intent.Approval.Candidate.Pending.IssuerFingerprint != s.fingerprint || len(s.issuer.SubjectKeyId) == 0 {
		return zero, ErrIntent
	}
	if verifyAuthority(s.issuer, s.root, now) != nil {
		return zero, ErrConfiguration
	}
	if customerissuance.ValidateIssuer(intent, s.issuer.Raw, s.root.Raw, now) != nil {
		return zero, ErrIntent
	}
	public, err := x509.ParsePKIXPublicKey(intent.Approval.Candidate.Pending.PublicKeyDER)
	if err != nil {
		return zero, ErrIntent
	}
	serial, ok := new(big.Int).SetString(intent.SerialHex, 16)
	if !ok || serial.Sign() <= 0 || serial.BitLen() > 128 {
		return zero, ErrIntent
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: intent.Approval.Candidate.DeviceID}, NotBefore: time.Unix(intent.NotBefore, 0).UTC(), NotAfter: time.Unix(intent.NotAfter, 0).UTC(), SignatureAlgorithm: x509.PureEd25519, BasicConstraintsValid: true, IsCA: false, MaxPathLen: -1, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, AuthorityKeyId: bytes.Clone(s.issuer.SubjectKeyId)}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	// Ed25519 and the fixed template are deterministic. The reader fails if
	// future code accidentally introduces entropy-dependent behavior.
	der, err := x509.CreateCertificate(noEntropy{}, template, s.issuer, public, s.key)
	if err != nil {
		return zero, ErrSigning
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	verified, err := customerissuance.VerifyIssued(der, s.issuer.Raw, s.root.Raw, intent, now)
	if err != nil {
		return zero, ErrSigning
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return verified, nil
}
