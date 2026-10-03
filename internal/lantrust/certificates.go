// Package lantrust implements explicit, public-certificate agent approvals for
// a separate mTLS telemetry listener. It never enrolls, issues credentials,
// reads private-key files, changes system trust, or opens a listener.
package lantrust

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"time"
)

const MaxCertificatePEMBytes = 64 * 1024
const maxChainCertificates = 8

var (
	ErrCertificate   = errors.New("certificate material is invalid for this role")
	ErrConfiguration = errors.New("agent trust configuration is invalid")
)

// Fingerprint is SHA-256 over the complete DER leaf, not a name or public key.
// Certificates with renewed validity or another signature require new approval.
func Fingerprint(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func parsePublicCertificates(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > MaxCertificatePEMBytes {
		return nil, ErrCertificate
	}
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		// pem.Decode otherwise silently skips a prefix, including malformed blocks.
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrCertificate
		}
		end := bytes.Index(raw, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, ErrCertificate
		}
		end += len("-----END CERTIFICATE-----")
		encoded, rest := raw[:end], raw[end:]
		if bytes.Count(encoded, []byte("-----BEGIN")) != 1 {
			return nil, ErrCertificate
		}
		block, extra := pem.Decode(encoded)
		if len(bytes.TrimSpace(extra)) != 0 {
			return nil, ErrCertificate
		}
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(certs) >= maxChainCertificates {
			return nil, ErrCertificate
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrCertificate
		}
		certs = append(certs, cert)
		raw = rest
	}
	if len(certs) == 0 {
		return nil, ErrCertificate
	}
	return certs, nil
}

func strongPublicKey(key any) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k != nil && k.N != nil && k.N.BitLen() >= 2048 && k.E >= 65537 && k.E%2 == 1
	case *ecdsa.PublicKey:
		return k != nil && k.X != nil && k.Y != nil && (k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()) && k.Curve.IsOnCurve(k.X, k.Y)
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	}
	return false
}

func validCertificate(cert *x509.Certificate, now time.Time) bool {
	if cert == nil || !strongPublicKey(cert.PublicKey) || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return false
	}
	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		return true
	}
	return false
}

func validLeaf(cert *x509.Certificate, role x509.ExtKeyUsage, now time.Time) bool {
	return validCertificate(cert, now) && !cert.IsCA && cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 &&
		len(cert.ExtKeyUsage) == 1 && cert.ExtKeyUsage[0] == role && len(cert.UnknownExtKeyUsage) == 0
}

func certificatePool(raw []byte, now time.Time) (*x509.CertPool, error) {
	certs, err := parsePublicCertificates(raw)
	if err != nil {
		return nil, ErrConfiguration
	}
	pool := x509.NewCertPool() // Deliberately never load the machine's system roots.
	seen := make(map[string]bool)
	for _, cert := range certs {
		if !validCertificate(cert, now) || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || seen[Fingerprint(cert)] {
			return nil, ErrConfiguration
		}
		pool.AddCert(cert)
		seen[Fingerprint(cert)] = true
	}
	return pool, nil
}

func verifyAgentChain(certs []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	if len(certs) == 0 || len(certs) > maxChainCertificates || !validLeaf(certs[0], x509.ExtKeyUsageClientAuth, now) {
		return ErrCertificate
	}
	intermediates := x509.NewCertPool()
	seen := map[string]bool{Fingerprint(certs[0]): true}
	for _, cert := range certs[1:] {
		if !validCertificate(cert, now) || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || seen[Fingerprint(cert)] {
			return ErrCertificate
		}
		seen[Fingerprint(cert)] = true
		intermediates.AddCert(cert)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return ErrCertificate
	}
	// The configured trust anchor's validity and key strength are checked again
	// on every request, as long-lived TLS sessions can outlive their certificates.
	for _, chain := range chains {
		valid := true
		for _, cert := range chain {
			valid = valid && validCertificate(cert, now)
		}
		if valid {
			return nil
		}
	}
	return ErrCertificate
}

func validateKeyPair(pair tls.Certificate, role x509.ExtKeyUsage, now time.Time) error {
	if len(pair.Certificate) == 0 || len(pair.Certificate) > maxChainCertificates {
		return ErrCertificate
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil || !validLeaf(leaf, role, now) {
		return ErrCertificate
	}
	key, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || key == nil || (reflect.ValueOf(key).Kind() == reflect.Pointer && reflect.ValueOf(key).IsNil()) {
		return ErrCertificate
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil || !bytes.Equal(pub, leaf.RawSubjectPublicKeyInfo) {
		return ErrCertificate
	}
	for _, raw := range pair.Certificate[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil || !validCertificate(cert, now) || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrCertificate
		}
	}
	if role == x509.ExtKeyUsageServerAuth && len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return ErrCertificate
	}
	return nil
}

// TLSConfig returns a fresh TLS 1.3 agent-listener configuration. The supplied
// server key stays in the standard tls.Config only; Registry never retains it.
// Callers must not relax this configuration or share the listener with operators.
func (r *Registry) TLSConfig(server tls.Certificate) (*tls.Config, error) {
	if r == nil || validateKeyPair(server, x509.ExtKeyUsageServerAuth, r.now()) != nil {
		return nil, ErrConfiguration
	}
	server.Leaf, _ = x509.ParseCertificate(server.Certificate[0])
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{server},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              r.roots.Clone(),
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.VerifiedChains) == 0 {
				return ErrUnauthorized
			}
			return verifyAgentChain(state.PeerCertificates, r.roots, r.now())
		},
	}, nil
}

// ClientTLSConfig uses only the explicit public server CA and a required DNS/IP
// server name. Go's normal chain and SAN verification remains enabled. The caller
// must use a dedicated transport with no proxy or redirects and an exact origin.
func ClientTLSConfig(client tls.Certificate, serverCAPEM []byte, serverName string) (*tls.Config, error) {
	now := time.Now().UTC()
	if !validServerName(serverName) || validateKeyPair(client, x509.ExtKeyUsageClientAuth, now) != nil {
		return nil, ErrConfiguration
	}
	roots, err := certificatePool(serverCAPEM, now)
	if err != nil {
		return nil, err
	}
	client.Leaf, _ = x509.ParseCertificate(client.Certificate[0])
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{client}, RootCAs: roots, ServerName: serverName}, nil
}

func validServerName(name string) bool {
	if ip, err := netip.ParseAddr(name); err == nil {
		return ip.Zone() == ""
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
