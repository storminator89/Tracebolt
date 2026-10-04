package inventorywire

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"localrmm/internal/fullinventory"
	"localrmm/internal/lantrust"
	"localrmm/internal/linuxpackages"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func inventoryFixture(t *testing.T) (tls.Certificate, *lantrust.Registry) {
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
func inventoryMessages(t *testing.T) (string, fullinventory.Manifest, []fullinventory.Chunk) {
	t.Helper()
	id, _ := GenerationID("agent_"+strings.Repeat("1", 32), 1)
	rows := []linuxpackages.PackageRow{{Name: "fixture-package", Version: "1.0", Architecture: "amd64", SourcePackage: "fixture-package", SourceVersion: "1.0", SourceMapping: "binary-default", InstallState: "installed"}}
	m, c, e := fullinventory.Build(context.Background(), fullinventory.SourceInventory{GenerationID: id, CollectedAt: time.Now().UTC().Add(-time.Minute), Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Rows: rows}, nil)
	if e != nil {
		t.Fatal(e)
	}
	hash, _ := fullinventory.ManifestDigest(m)
	return hash, m, c
}
func TestCompleteWireStrictAllPurposeMessages(t *testing.T) {
	hash, m, chunks := inventoryMessages(t)
	for _, tc := range []struct {
		op, hash string
		payload  any
	}{{"begin", hash, m}, {"append", hash, chunks[0]}, {"finalize", hash, struct{}{}}, {"abort", hash, struct{}{}}, {"status", hash, struct{}{}}, {"failure", "", map[string]string{"attemptedAt": m.CollectedAt.Format(time.RFC3339Nano), "reason": "source_missing"}}} {
		raw, e := EncodeMessage(tc.op, 1, m.GenerationID, tc.hash, tc.payload)
		if e != nil {
			t.Fatal(tc.op, e)
		}
		parsed, e := DecodeMessage(tc.op, raw)
		if e != nil || parsed.Sequence != 1 || parsed.GenerationID != m.GenerationID {
			t.Fatal("valid operation rejected")
		}
		for _, bad := range [][]byte{bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":1`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1), bytes.Replace(raw, []byte(`"sequence":"1"`), []byte(`"sequence":"1","sequence":"1"`), 1), append(raw, []byte(`{}`)...), bytes.Replace(raw, []byte(`"generationId"`), []byte(`"GenerationId"`), 1)} {
			if _, e := DecodeMessage(tc.op, bad); e == nil {
				t.Fatal("ambiguous contract accepted")
			}
		}
	}
	if _, e := EncodeMessage("finalize", 1, m.GenerationID, hash, map[string]bool{"complete": true}); e == nil {
		t.Fatal("client asserted completion payload accepted")
	}
	if _, e := EncodeMessage("failure", 1, m.GenerationID, "", map[string]string{"attemptedAt": m.CollectedAt.Format(time.RFC3339Nano), "reason": "private diagnostic"}); e == nil {
		t.Fatal("raw reason accepted")
	}
}
func TestCompleteWireProofIsPurposeBoundAndNotCollectionTime(t *testing.T) {
	pair, registry := inventoryFixture(t)
	hash, m, _ := inventoryMessages(t)
	raw, e := EncodeMessage("begin", 1, m.GenerationID, hash, m)
	if e != nil {
		t.Fatal(e)
	}
	verifier, e := New(Config{Origin: "http://127.0.0.1:8788", Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	makeRequest := func() *http.Request {
		r, e := NewSignedRequest(context.Background(), "http://127.0.0.1:8788", pair, "begin", 1, time.Now().UTC(), raw)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	verified, e := verifier.Verify(makeRequest())
	if e != nil || !bytes.Equal(verified.Body, raw) || verified.Sequence != 1 {
		t.Fatal("valid inventory proof rejected")
	}
	parsed, e := DecodeMessage("begin", verified.Body)
	if e != nil || !parsed.Manifest.CollectedAt.Equal(m.CollectedAt) || verified.SignedAt.Equal(m.CollectedAt) {
		t.Fatal("proof time changed collection age")
	}
	for _, modify := range []func(*http.Request){func(r *http.Request) { r.URL.Path = PathPrefix + "finalize" }, func(r *http.Request) { r.Header["x-tracebolt-inventory-sequence"] = []string{"1"} }, func(r *http.Request) { r.Header.Set("Origin", "http://127.0.0.1:8788") }, func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, func(r *http.Request) { r.URL.RawQuery = "x=1" }} {
		r := makeRequest()
		modify(r)
		if _, e := verifier.Verify(r); e == nil {
			t.Fatal("invalid purpose/framing accepted")
		}
	}
	if _, e = NewSignedRequest(context.Background(), "http://127.0.0.1:8788", pair, "operator", 1, time.Now().UTC(), raw); e == nil {
		t.Fatal("unregistered purpose signed")
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil {
		t.Fatal("fixture JSON")
	}
}

func TestCompleteWireStandaloneVerifierRejectsAmbiguousFraming(t *testing.T) {
	pair, registry := inventoryFixture(t)
	hash, m, _ := inventoryMessages(t)
	raw, e := EncodeMessage("begin", 1, m.GenerationID, hash, m)
	if e != nil {
		t.Fatal(e)
	}
	v, e := New(Config{Origin: "http://127.0.0.1:8788", Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header["content-length"] = []string{"01"} },
		func(r *http.Request) { r.Header["Content-Length"] = []string{"1", "1"} },
		func(r *http.Request) { r.Header["Expect"] = []string{"100-continue"} },
		func(r *http.Request) { r.Header["Upgrade"] = []string{"fixture"} },
		func(r *http.Request) { r.Header["Host"] = []string{"elsewhere.test"} },
		func(r *http.Request) { r.Header["Transfer-Encoding"] = []string{"chunked"} },
	} {
		r, e := NewSignedRequest(context.Background(), "http://127.0.0.1:8788", pair, "begin", 1, time.Now().UTC(), raw)
		if e != nil {
			t.Fatal(e)
		}
		change(r)
		if _, e = v.Verify(r); e != ErrRequest {
			t.Fatal("standalone framing differed from ingress", e)
		}
	}
}
