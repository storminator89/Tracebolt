package systemwire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/inventorywire"
	"localrmm/internal/lantrust"
	"localrmm/internal/systeminventory"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func systemFixture(t *testing.T) (tls.Certificate, *lantrust.Registry) {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	ca, _ = x509.ParseCertificate(der)
	leafPub, leafKey, _ := ed25519.GenerateKey(rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, leafPub, key)
	if e != nil {
		t.Fatal(e)
	}
	registry, e := lantrust.NewRegistry(context.Background(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), lantrust.NewMemoryStore())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = registry.Approve(context.Background(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), "invented fixture"); e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, registry
}

func TestSystemWireStrictFrameReceiptAndSeparateDomain(t *testing.T) {
	id := "agent_" + strings.Repeat("1", 32)
	generation, e := GenerationID(id, 1)
	if e != nil {
		t.Fatal(e)
	}
	old, _ := inventorywire.GenerationID(id, 1)
	if old == generation {
		t.Fatal("sequence domains overlap")
	}
	now := time.Now().UTC()
	snapshot := systeminventory.Empty(generation, now, systeminventory.ReasonSourceMissing)
	raw, e := Encode(1, snapshot)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := Decode(raw)
	if e != nil || parsed.Sequence != 1 {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), append(bytes.Clone(raw), []byte(`{}`)...)} {
		if _, e = Decode(bad); e == nil {
			t.Fatal("ambiguous frame accepted")
		}
	}
	digest := sha256.Sum256(raw)
	receipt := Receipt{ReceiptVersion, id, 1, generation, now, now.Add(time.Second), hex.EncodeToString(digest[:])}
	encoded, _ := json.Marshal(receipt)
	if _, e = DecodeReceipt(encoded, id, raw); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{bytes.Replace(encoded, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), append(bytes.Clone(encoded), []byte(`{}`)...), bytes.Replace(encoded, []byte(`"bodyHash"`), []byte(`"BodyHash"`), 1)} {
		if _, e = DecodeReceipt(bad, id, raw); e == nil {
			t.Fatal("ambiguous receipt accepted")
		}
	}
	if _, e = DecodeReceipt(encoded, id, append([]byte(" "), raw...)); e == nil {
		t.Fatal("receipt adopted for altered exact bytes")
	}
}

func TestSystemWireHTTPProofAndFraming(t *testing.T) {
	pair, registry := systemFixture(t)
	id := "agent_" + strings.Repeat("1", 32)
	generation, _ := GenerationID(id, 1)
	raw, e := Encode(1, systeminventory.Empty(generation, time.Now().UTC().Add(-time.Minute), systeminventory.ReasonSourceMissing))
	if e != nil {
		t.Fatal(e)
	}
	origin := "http://127.0.0.1:8788"
	verifier, e := New(Config{Origin: origin, Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	request := func() *http.Request {
		r, e := NewSignedRequest(context.Background(), origin, pair, 1, time.Now().UTC(), raw)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	verified, e := verifier.Verify(request())
	if e != nil || !bytes.Equal(verified.Body, raw) || verified.Sequence != 1 {
		t.Fatal("valid system proof", e)
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.URL.Path = inventorywire.PathPrefix + "begin" }, func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, func(r *http.Request) { r.Header.Set("Cookie", "x") }, func(r *http.Request) { r.Header.Set("Expect", "100-continue") }, func(r *http.Request) { r.Header["content-length"] = []string{"01"} }, func(r *http.Request) { r.URL.ForceQuery = true }} {
		r := request()
		change(r)
		if _, e = verifier.Verify(r); e == nil {
			t.Fatal("invalid context/framing accepted")
		}
	}
	if _, e = NewSignedRequest(context.Background(), origin, pair, 1, time.Now().UTC(), make([]byte, MaxBodyBytes+1)); e == nil {
		t.Fatal("oversized system body signed")
	}
}
