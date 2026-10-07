//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclientstate"
	"localrmm/internal/lantrust"
	"localrmm/internal/model"
	"localrmm/internal/signedhttp"
	"localrmm/internal/windowsmanaged"
)

// All certificates and state are disposable fixtures. No listener, actual host
// collector, credential store, service manager or ACL operation is used.
func windowsMaterialFixture(t *testing.T, transport string) Material {
	t.Helper()
	at := time.Now().UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	cert := &x509.Certificate{SerialNumber: big.NewInt(19), NotBefore: at.Add(-time.Hour), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pair := tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}
	dir := t.TempDir()
	c := windowsConfig(Config{ManagerOrigin: "https://fixture.invalid", AgentID: "agent_" + strings.Repeat("1", 32), CertificateFile: filepath.Join(dir, "cert.pem"), PrivateKeyFile: filepath.Join(dir, "key.pem"), ServerCAFile: filepath.Join(dir, "ca.pem"), StateDirectory: filepath.Join(dir, "sender")})
	m := Material{config: c, certificate: pair, loaded: true, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool(), ServerName: "fixture.invalid", Certificates: []tls.Certificate{pair}}}
	if transport == "http-test" {
		m.config.Profile, m.config.ManagerOrigin, m.config.ServerCAFile, m.config.InsecureHTTPAcknowledged = transport, "http://fixture.invalid", "", true
		m.tlsConfig = nil
	}
	binding := senderBinding(m.config, leaf)
	m.binding = hex.EncodeToString(binding[:])
	if !m.valid() {
		t.Fatal("invalid inert material")
	}
	return m
}

type windowsPublicFixture struct {
	raw []byte
	id  string
}

func (f windowsPublicFixture) AuthorizePublicCertificate(raw []byte) (lantrust.Agent, error) {
	block, _ := pem.Decode(raw)
	if block == nil || !bytes.Equal(block.Bytes, f.raw) {
		return lantrust.Agent{}, errors.New("wrong fixture certificate")
	}
	return lantrust.Agent{ID: f.id}, nil
}

func TestWindowsInventoryExactRetryAndHTTPPathSignature(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		t.Run(transport, func(t *testing.T) {
			m := windowsMaterialFixture(t, transport)
			state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
			if err != nil {
				t.Fatal(err)
			}
			defer state.Close()
			var bodies [][]byte
			var signatures []string
			var verifier *signedhttp.Verifier
			if transport == "http-test" {
				verifier, err = signedhttp.New(signedhttp.Config{Origin: m.config.ManagerOrigin, Path: signedhttp.WindowsPath, Registry: windowsPublicFixture{m.certificate.Certificate[0], m.config.AgentID}})
				if err != nil {
					t.Fatal(err)
				}
			}
			send := func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != WindowsTelemetryPath {
					t.Fatal("request used Linux ingress")
				}
				var raw []byte
				if verifier != nil {
					v, err := verifier.Verify(r)
					if err != nil {
						t.Fatal("Windows signed path rejected", err)
					}
					raw = v.Body
					var decoded frame
					json.Unmarshal(raw, &decoded)
					if v.Sequence != decoded.Sequence || !v.SignedAt.Equal(decoded.Observation.GeneratedAt) {
						t.Fatal("signature metadata mismatch")
					}
				} else {
					raw, _ = io.ReadAll(r.Body)
				}
				bodies = append(bodies, bytes.Clone(raw))
				signatures = append(signatures, r.Header.Get(signedhttp.SignatureHeader))
				if len(bodies) == 1 {
					return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
				}
				var f frame
				json.Unmarshal(raw, &f)
				body, _ := json.Marshal(receipt{SchemaVersion: "tracebolt.agent-receipt.v1", AgentID: m.config.AgentID, Sequence: f.Sequence, CollectedAt: f.Observation.Observation.LastSeen, ReceivedAt: time.Now().UTC(), Duplicate: true})
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))}, nil
			}
			calls := 0
			collect := func(ctx context.Context, id string) (windowsmanaged.Snapshot, model.Device, error) {
				calls++
				return windowsSource(ctx, id)
			}
			first, err := runUsingStateWithDependencies(context.Background(), m, state, nil, nil, nil, collect, send)
			if !errors.Is(err, ErrTransport) || first.Sequence != 1 {
				t.Fatal("first transport failure not retained", err)
			}
			pending, _ := state.Pending()
			before := pending.Body()
			second, err := runUsingStateWithDependencies(context.Background(), m, state, nil, nil, nil, collect, send)
			if err != nil || !second.RetriedPending || !second.Duplicate || calls != 1 || len(bodies) != 2 || !bytes.Equal(before, bodies[0]) || !bytes.Equal(bodies[0], bodies[1]) || signatures[0] != signatures[1] {
				t.Fatal("pending retry recollected, mutated or resigned differently", err)
			}
			pending, _ = state.Pending()
			next, _ := state.NextSequence()
			if pending != nil || next != 2 {
				t.Fatal("acknowledgement lost counter")
			}
		})
	}
}

func TestWindowsInventoryRuntimeAndLedgerIsolation(t *testing.T) {
	for _, transport := range []string{"tls", "http-test"} {
		m := windowsMaterialFixture(t, transport)
		if _, err := Run(context.Background(), m); !errors.Is(err, ErrConfiguration) {
			t.Fatal("Linux attempted Windows runtime", err)
		}
		if _, err := os.Stat(m.config.StateDirectory); !os.IsNotExist(err) {
			t.Fatal("platform rejection opened state")
		}
		leaf, _ := x509.ParseCertificate(m.certificate.Certificate[0])
		for _, old := range []struct{ version, profile string }{{ConfigVersion, ""}, {GuidedConfigVersion, ""}, {OperationalConfigVersion, enrollmentcrypto.CollectionProfileOperational}, {PackageConfigVersion, enrollmentcrypto.CollectionProfilePackages}, {CompleteConfigVersion, enrollmentcrypto.CollectionProfileComplete}} {
			c := m.config
			c.SchemaVersion, c.CollectionProfile = old.version, old.profile
			binding := senderBinding(c, leaf)
			if hex.EncodeToString(binding[:]) == m.binding {
				t.Fatal("Windows reuses older binding")
			}
			dir := filepath.Join(t.TempDir(), "old-state")
			state, err := lanclientstate.InitializeNew(dir, hex.EncodeToString(binding[:]))
			if err != nil {
				t.Fatal(err)
			}
			state.Close()
			before, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			if state, err := lanclientstate.OpenExisting(dir, m.binding); err == nil {
				state.Close()
				t.Fatal("Windows adopted old ledger")
			}
			after, _ := os.ReadFile(filepath.Join(dir, "state.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("rejected ledger modified")
			}
		}
	}
}

func TestWindowsInventoryWrongPendingAndExpiredCounter(t *testing.T) {
	m := windowsMaterialFixture(t, "http-test")
	state, err := lanclientstate.InitializeNew(m.config.StateDirectory, m.binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f, raw, err := collectWindowsFrame(context.Background(), m.config, 1, windowsSource)
	if err != nil {
		t.Fatal(err)
	}
	// A mismatched profile is retained unchanged rather than discarded/recollected.
	f.SchemaVersion = FrameVersion
	bad, _ := json.Marshal(f)
	p, err := state.Stage(1, bad)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runUsingStateWithDependencies(context.Background(), m, state, nil, nil, nil, func(context.Context, string) (windowsmanaged.Snapshot, model.Device, error) {
		t.Fatal("bad pending recollected")
		return windowsmanaged.Snapshot{}, model.Device{}, nil
	}, func(*http.Request) (*http.Response, error) { t.Fatal("bad pending sent"); return nil, nil })
	if !errors.Is(err, ErrState) {
		t.Fatal("wrong frame accepted")
	}
	after, _ := state.Pending()
	if after == nil || after.Digest != p.Digest || !bytes.Equal(after.Body(), bad) {
		t.Fatal("wrong frame mutated")
	}
	if state.Discard(p.Digest) != nil {
		t.Fatal("fixture discard")
	}
	f.SchemaVersion = FrameWindowsInventoryVersion
	f.Sequence = 2
	old := time.Now().UTC().Add(-10 * time.Minute)
	f.WindowsInventory.CollectedAt = old
	f.Observation.GeneratedAt = old
	d := &f.Observation.Observation
	d.LastSeen = old
	d.CPU.CollectedAt = old
	d.Memory.CollectedAt = old
	d.Disk.CollectedAt = old
	for i := range d.Evidence {
		d.Evidence[i].CollectedAt = old
	}
	staleRaw, _ := json.Marshal(f)
	if _, err := state.Stage(2, staleRaw); err != nil {
		t.Fatal(err)
	}
	calls := 0
	report, err := runUsingStateWithDependencies(context.Background(), m, state, nil, nil, nil, func(ctx context.Context, id string) (windowsmanaged.Snapshot, model.Device, error) {
		calls++
		return windowsSource(ctx, id)
	}, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
	})
	if !errors.Is(err, ErrTransport) || !report.DiscardedStale || report.RetriedPending || report.Sequence != 3 || calls != 1 {
		t.Fatal("expired pending reused sequence", err)
	}
	pending, _ := state.Pending()
	if pending == nil || pending.Sequence != 3 || bytes.Equal(pending.Body(), raw) {
		t.Fatal("fresh pending missing")
	}
}
