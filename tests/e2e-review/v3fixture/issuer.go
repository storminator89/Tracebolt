package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"localrmm/internal/enrollmentissuer"
	"math/big"
	"time"
)

func makeIssuer(now time.Time) (*enrollmentissuer.Issuer, error) {
	rp, rk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	defer clear(rk)
	ip, ik, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	rh, ih := sha256.Sum256(rp), sha256.Sum256(ip)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable browser fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(60 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: rh[:20]}
	rd, e := x509.CreateCertificate(rand.Reader, root, root, rp, rk)
	if e != nil {
		return nil, e
	}
	root, e = x509.ParseCertificate(rd)
	if e != nil {
		return nil, e
	}
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Disposable browser fixture issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: ih[:20]}
	der, e := x509.CreateCertificate(rand.Reader, intermediate, root, ip, rk)
	if e != nil {
		return nil, e
	}
	fp := sha256.Sum256(der)
	return enrollmentissuer.New(der, rd, ik, hex.EncodeToString(fp[:]), now)
}
