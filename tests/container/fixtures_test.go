package container_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/crypto/argon2"
	"localrmm/internal/bundle"
	"localrmm/internal/lanstore"
	"localrmm/internal/model"
	"localrmm/internal/signedhttp"
	"math/big"
	"net"
	"testing"
	"time"
)

type credentials struct {
	ca, serverCert, serverKey, clientPEM []byte
	client                               tls.Certificate
	password, hash                       string
}

func fixtureCredentials(t *testing.T) credentials {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture key")
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Disposable Tracebolt container smoke CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	raw, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture CA")
	}
	ca, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal("fixture CA parse")
	}
	result := credentials{ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})}
	leaf := func(serial int64, role x509.ExtKeyUsage) ([]byte, []byte, tls.Certificate) {
		pub, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal("fixture leaf key")
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{role}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, template, ca, pub, key)
		if e != nil {
			t.Fatal("fixture leaf")
		}
		pk, e := x509.MarshalPKCS8PrivateKey(k)
		if e != nil {
			t.Fatal("fixture private format")
		}
		cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk})
		pair, e := tls.X509KeyPair(cert, priv)
		if e != nil {
			t.Fatal("fixture pair")
		}
		pair.Leaf, _ = x509.ParseCertificate(der)
		return cert, priv, pair
	}
	result.serverCert, result.serverKey, _ = leaf(2, x509.ExtKeyUsageServerAuth)
	result.clientPEM, _, result.client = leaf(3, x509.ExtKeyUsageClientAuth)
	salt := make([]byte, 16)
	pass := make([]byte, 24)
	if _, err = rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	if _, err = rand.Read(pass); err != nil {
		t.Fatal(err)
	}
	result.password = base64.RawURLEncoding.EncodeToString(pass)
	hash := argon2.IDKey([]byte(result.password), salt, 2, 65536, 1, 32)
	result.hash = "$argon2id$v=19$m=65536,t=2,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash)
	return result
}

// Fabricated unknown metrics: no host collection or real endpoint data.
func fixtureFrame(t *testing.T) []byte {
	t.Helper()
	now := time.Now().UTC()
	metric := model.Metric{Unit: "%", Quality: "unknown", Source: "container test fixture only", CollectedAt: now}
	d := model.Device{ID: "sandbox-local", Name: "Local sandbox", Platform: "linux", OS: "Fixture", Site: "Cloud sandbox", Group: "Local observations", Status: "unknown", Source: "sandbox", LastSeen: now, AgentVersion: "fixture", Uptime: "Unknown", CPU: metric, Memory: metric, Disk: metric}
	raw, e := bundle.Encode(d)
	if e != nil {
		t.Fatal("fixture bundle invalid")
	}
	var b bundle.Bundle
	if json.Unmarshal(raw, &b) != nil {
		t.Fatal("fixture decode")
	}
	out, e := json.Marshal(lanstore.Frame{SchemaVersion: lanstore.FrameVersion, Sequence: 1, Observation: b})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = lanstore.ValidateFrame(out, time.Now().UTC()); e != nil {
		t.Fatal("fixture frame invalid")
	}
	return out
}
func TestFixtureFrameContract(t *testing.T) { fixtureFrame(t) }

func TestHTTPFixtureSigningContract(t *testing.T) {
	c := fixtureCredentials(t)
	raw := fixtureFrame(t)
	var frame lanstore.Frame
	if json.Unmarshal(raw, &frame) != nil {
		t.Fatal("fixture frame")
	}
	req, err := signedhttp.NewSignedRequest(context.Background(), "http://127.0.0.1:8788", c.client, frame.Sequence, frame.Observation.GeneratedAt, raw)
	if err != nil || req.Header.Get(signedhttp.SignatureHeader) == "" {
		t.Fatal("HTTP fixture signature contract")
	}
}
