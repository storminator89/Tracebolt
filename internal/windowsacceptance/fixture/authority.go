package fixture

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"localrmm/internal/enrollmentissuer"
)

// This exceptional root generation is exclusively disposable test authority.
// The root private key lives only in this call, never in the fixture handle or
// filesystem. It is not provisioning for a production or ordinary LAN manager.
func newDisposableAuthority(now time.Time) (*enrollmentissuer.Issuer, tls.Certificate, error) {
	bad := func() (*enrollmentissuer.Issuer, tls.Certificate, error) { return nil, tls.Certificate{}, ErrFixture }
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return bad()
	}
	defer clear(rk)
	ip, ik, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return bad()
	}
	defer clear(ik)
	sp, sk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return bad()
	}
	ok := false
	defer func() {
		if !ok {
			clear(sk)
		}
	}()
	now = now.UTC()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable Windows acceptance root; not production"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte("windows-acceptance-root")}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		return bad()
	}
	root, e = x509.ParseCertificate(rd)
	if e != nil {
		return bad()
	}
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable Windows acceptance client-only issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: []byte("windows-acceptance-issuer")}
	id, e := x509.CreateCertificate(rand.Reader, intermediate, root, ip, rk)
	if e != nil {
		return bad()
	}
	issuer, e := enrollmentissuer.New(id, rd, ik, digest(id), now)
	if e != nil {
		return bad()
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Disposable loopback Windows acceptance peer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, root, sp, rk)
	if e != nil {
		return bad()
	}
	ok = true
	return issuer, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: sk}, nil
}

func publicPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
