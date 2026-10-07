package enrollmentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
)

type windowsEnrollmentTransport func(*http.Request) (*http.Response, error)

func (f windowsEnrollmentTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWindowsInventoryFixedEnrollmentRoutes(t *testing.T) {
	for _, collection := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfileWindowsInventory} {
		calls := 0
		client := &http.Client{Transport: windowsEnrollmentTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			prefix := "/v2/enrollment/"
			if collection == enrollmentcrypto.CollectionProfileWindowsInventory {
				prefix = WindowsEnrollmentPathPrefix
			}
			if r.URL.Scheme != "https" || r.URL.Host != "fixture.invalid" || !strings.HasPrefix(r.URL.Path, prefix) {
				t.Fatal("wrong fixed protocol destination")
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
		})}
		w := wireClient{client: client, origin: "https://fixture.invalid", collectionProfile: collection}
		for _, verb := range []string{"challenge", "claim", "status", "credential", "activate"} {
			if _, err := w.post(context.Background(), verb, []byte(`{}`)); err != nil {
				t.Fatal(err)
			}
		}
		for _, path := range []string{"", "../claim", "status?x=1", "/v2/enrollment/claim", "https://other.invalid"} {
			if _, err := w.post(context.Background(), path, []byte(`{}`)); !errors.Is(err, ErrResponse) {
				t.Fatal("caller path accepted")
			}
		}
		if calls != 5 {
			t.Fatal("invalid path reached transport")
		}
	}
}

func TestWindowsInventoryHandoffUsesDistinctConfigAndDisclosesScope(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, ed25519.SeedSize))
	s := &session{&sessionData{opts: Options{StateDirectory: t.TempDir()}, key: key,
		l: ledger{&ledgerData{Activated: true, Bootstrap: Bootstrap{Profile: "tls", AgentOrigin: "https://fixture.invalid", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory},
			Intent: enrollmentcrypto.Intent{DeviceID: "agent_" + strings.Repeat("1", 32)}, CertificateDER: base64.RawStdEncoding.EncodeToString([]byte("inert fixture public certificate bytes"))}}}}
	c, files, _, err := s.handoff()
	defer clearArtifacts(files)
	if err != nil || c.SchemaVersion != lanclient.WindowsInventoryConfigVersion || c.CollectionProfile != enrollmentcrypto.CollectionProfileWindowsInventory || c.Profile != "tls" || c.StateDirectory != filepath.Join(s.opts.StateDirectory, "telemetry") {
		t.Fatal("Windows handoff lost profile", err)
	}
	for _, word := range []string{"hostname", "IP addresses", "process", "service", "software", "CPU", "partial", "denied", "event content", "remote actions", "updates", "fresh", "TLS"} {
		if !strings.Contains(WindowsInventoryPrivacy, word) {
			t.Fatal("missing explicit privacy category", word)
		}
	}
}

func TestWindowsInventoryFreshConsentRequiredBeforeStateOrDisplay(t *testing.T) {
	called := false
	b := Bootstrap{Profile: "tls", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory}
	_, err := Run(context.Background(), b, Options{StateDirectory: filepath.Join(t.TempDir(), "unused"), Display: func(TrustDisplay) error { called = true; return nil }})
	if !errors.Is(err, ErrBootstrap) || called {
		t.Fatal("unacknowledged Windows inventory reached state or display")
	}
}

func TestWindowsInventoryHTTPHandoffKeepsExplicitTransportBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	s := &session{&sessionData{opts: Options{StateDirectory: t.TempDir(), InsecureHTTPAcknowledged: true, WindowsInventoryAcknowledged: true}, key: key,
		l: ledger{&ledgerData{Activated: true, Bootstrap: Bootstrap{Profile: "http-test", AgentOrigin: "http://fixture.invalid", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory}, Intent: enrollmentcrypto.Intent{DeviceID: "agent_" + strings.Repeat("1", 32)}, CertificateDER: base64.RawStdEncoding.EncodeToString([]byte("inert public certificate"))}}}}
	c, files, ready, err := s.handoff()
	defer clearArtifacts(files)
	if err != nil || c.SchemaVersion != lanclient.WindowsInventoryConfigVersion || c.Profile != "http-test" || !c.InsecureHTTPAcknowledged || c.ServerCAFile != "" || !bytes.Contains(ready, []byte(`"serverAuthenticated":false`)) {
		t.Fatal("HTTP handoff lost disclosure or asserted server authentication", err)
	}
	s.opts.InsecureHTTPAcknowledged = false
	_, files, _, err = s.handoff()
	defer clearArtifacts(files)
	if err == nil {
		t.Fatal("unacknowledged plaintext handoff allowed")
	}
}
