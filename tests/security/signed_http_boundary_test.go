package security_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"localrmm/internal/api"
	"localrmm/internal/lanstore"
	"localrmm/internal/lantrust"
	"localrmm/internal/signedhttp"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func makeReviewSigningLeaf(t *testing.T, ca reviewCA) (tls.Certificate, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Synthetic HTTP-test signing identity"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(10 * time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key, Leaf: leaf}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
}

func TestIndependentSignedHTTPBindingAndAtomicAcceptance(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only manager storage")
	}
	state, err := lanstore.Open(filepath.Join(t.TempDir(), "private", "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	ca := makeReviewCA(t)
	registry, err := lantrust.NewRegistry(context.Background(), ca.pem, state)
	if err != nil {
		t.Fatal(err)
	}
	leaf, public := makeReviewSigningLeaf(t, ca)
	agent, err := registry.Approve(context.Background(), public, "Synthetic HTTP-test alias")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "http://" + server.Listener.Addr().String()
	server.Config.Handler, err = api.NewHTTPTestIngressHandler(registry, state, origin)
	if err != nil {
		t.Fatal(err)
	}
	server.Start()
	defer server.Close()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	frame, body := reviewLANFrame(t)
	request := func(sequence uint64, raw []byte) *http.Request {
		t.Helper()
		r, e := signedhttp.NewSignedRequest(context.Background(), origin, leaf, sequence, frame.Observation.GeneratedAt, raw)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	call := func(r *http.Request) (int, []byte) {
		t.Helper()
		res, e := client.Do(r)
		if e != nil {
			t.Fatal("ephemeral signed HTTP request failed")
		}
		defer res.Body.Close()
		data, e := io.ReadAll(io.LimitReader(res.Body, 8192))
		if e != nil {
			t.Fatal(e)
		}
		return res.StatusCode, data
	}
	code, data := call(request(1, body))
	if code != 200 {
		t.Fatalf("signed valid frame status %d", code)
	}
	var first lanstore.Receipt
	if json.Unmarshal(data, &first) != nil || first.AgentID != agent.ID {
		t.Fatal("signed identity mapping failed")
	}
	code, data = call(request(1, body))
	var duplicate lanstore.Receipt
	if json.Unmarshal(data, &duplicate) != nil || code != 200 || !duplicate.Duplicate || !duplicate.ReceivedAt.Equal(first.ReceivedAt) {
		t.Fatal("signed retry refreshed receipt time")
	}
	changed := request(1, body)
	altered := append(append([]byte{}, body...), ' ')
	changed.Body = io.NopCloser(bytes.NewReader(altered))
	changed.ContentLength = int64(len(altered))
	if code, _ = call(changed); code != 403 {
		t.Fatal("changed payload retained signature authority")
	}
	changed = request(1, body)
	changed.Header.Add(signedhttp.SequenceHeader, "1")
	if code, _ = call(changed); code != 403 {
		t.Fatal("duplicate signature header accepted")
	}
	changed = request(1, body)
	changed.Header.Set("Cookie", "synthetic=value")
	if code, _ = call(changed); code == 200 {
		t.Fatal("browser credential accepted on signed agent surface")
	}
	changed = request(1, body)
	changed.URL.Path = "/api/auth/session"
	if code, _ = call(changed); code == 200 {
		t.Fatal("signature authorized operator endpoint")
	}
	frame.Sequence = 2
	frame.Observation.GeneratedAt = frame.Observation.GeneratedAt.Add(time.Millisecond)
	d := &frame.Observation.Observation
	d.LastSeen = d.LastSeen.Add(time.Millisecond)
	d.CPU.CollectedAt = d.CPU.CollectedAt.Add(time.Millisecond)
	d.Memory.CollectedAt = d.Memory.CollectedAt.Add(time.Millisecond)
	d.Disk.CollectedAt = d.Disk.CollectedAt.Add(time.Millisecond)
	for i := range d.Evidence {
		d.Evidence[i].CollectedAt = d.Evidence[i].CollectedAt.Add(time.Millisecond)
	}
	body, err = json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ = call(request(3, body)); code != 400 {
		t.Fatal("signed header/frame sequence disagreement accepted")
	}
	if code, _ = call(request(2, body)); code != 200 {
		t.Fatal("rejected frame consumed sequence outside observation transaction")
	}
	verifier, err := signedhttp.New(signedhttp.Config{Origin: origin, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	tlsAttempt := request(2, body)
	tlsAttempt.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true}
	if _, err = verifier.Verify(tlsAttempt); err == nil {
		t.Fatal("HTTP signature became TLS authentication fallback")
	}
	if err = registry.Revoke(context.Background(), agent.ID); err != nil {
		t.Fatal(err)
	}
	if code, _ = call(request(2, body)); code != 403 {
		t.Fatal("revoked signing identity accepted")
	}
}
