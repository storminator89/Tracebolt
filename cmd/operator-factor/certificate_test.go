package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPublicCertificateFileRejectsPrivateOrMixedMaterial(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic-public-certificate"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privateBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte(credentialCanary)})
	dir := filepath.Join(t.TempDir(), "private")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{{"der", der, true}, {"pem", encoded, true}, {"public-chain", append(append([]byte(nil), encoded...), encoded...), true}, {"private", privateBlock, false}, {"mixed", append(append([]byte(nil), encoded...), privateBlock...), false}, {"trailing", append(append([]byte(nil), encoded...), []byte(credentialCanary)...), false}, {"leading", append([]byte(credentialCanary), encoded...), false}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if err := os.WriteFile(path, tc.data, 0600); err != nil {
				t.Fatal(err)
			}
			got, err := readPublicCertificate(path)
			if tc.valid {
				if err != nil || !bytes.Equal(got, der) {
					t.Fatal("public certificate fixture rejected")
				}
			} else if err == nil || len(got) != 0 {
				t.Fatal("nonpublic material accepted")
			}
		})
	}
}
