package lantrust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func FuzzStrictPublicCertificatePEM(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		f.Fatal(err)
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	f.Add(public)
	f.Add(append([]byte("junk\n"), public...))
	f.Add(append([]byte("-----BEGIN CERTIFICATE-----\nbroken\n"), public...))
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nZg==\n-----END PRIVATE KEY-----"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, input []byte) {
		certs, err := parsePublicCertificates(input)
		if err != nil {
			return
		}
		if len(input) > MaxCertificatePEMBytes || len(certs) == 0 || len(certs) > maxChainCertificates {
			t.Fatal("accepted out-of-bounds certificate input")
		}
		if bytes.Contains(input, []byte("PRIVATE KEY")) {
			t.Fatal("accepted private-key material")
		}
		for _, cert := range certs {
			if cert == nil || len(cert.Raw) == 0 || len(Fingerprint(cert)) != 64 {
				t.Fatal("invalid parsed certificate")
			}
		}
	})
}
