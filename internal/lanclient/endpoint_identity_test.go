//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"localrmm/internal/endpointidentity"
	"localrmm/internal/systeminventory"
	"localrmm/internal/systemwire"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func prepareEndpointHandoff(t *testing.T, m Material) (Material, string) {
	t.Helper()
	c := completeConfig(m.config)
	if InitializeGuidedState(c) != nil {
		t.Fatal("state fixture")
	}
	material, e := loadConfig(c)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(filepath.Dir(c.PrivateKeyFile), "agent.json")
	raw, _ := json.Marshal(c)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("config fixture")
	}
	h := sha256.Sum256(raw)
	leaf := sha256.Sum256(material.certificate.Certificate[0])
	ready, _ := json.Marshal(map[string]any{"version": "tracebolt.enrollment-ready.v2", "configHash": hex.EncodeToString(h[:]), "certificateHash": hex.EncodeToString(leaf[:]), "serverAuthenticated": c.Profile == "tls"})
	if os.WriteFile(filepath.Join(filepath.Dir(path), "ready.json"), ready, 0600) != nil {
		t.Fatal("ready fixture")
	}
	return material, path
}
func consentFixture(t *testing.T, m Material) {
	t.Helper()
	raw, e := endpointidentity.EncodeLocalConsent(endpointidentity.LocalConsent{SchemaVersion: endpointidentity.ConsentVersion, ExtensionVersion: endpointidentity.SchemaVersion, Scope: endpointidentity.Scope, SenderBinding: m.binding, Acknowledged: true}, m.binding)
	if e != nil || writeEndpointConsent(m, raw) != nil {
		t.Fatal("consent fixture", e)
	}
}
func TestEndpointConsentAdminIsQuiescentLocalAndPreservesLedgers(t *testing.T) {
	var network atomic.Int32
	f := integrationFixture(t, "tls", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { network.Add(1); next.ServeHTTP(w, r) })
	})
	m, path := prepareEndpointHandoff(t, f.material)
	owner, e := openSenderState(m)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ConfigureEndpointIdentity(path, "enable", true); e == nil {
		t.Fatal("active sender allowed consent change")
	}
	owner.Close()
	paths := []string{filepath.Join(m.config.StateDirectory, "state.json"), filepath.Join(m.config.StateDirectory, "inventory", "ledger.json"), filepath.Join(m.config.StateDirectory, "system", "system-state.json")}
	before := map[string][]byte{}
	for _, p := range paths {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		before[p] = b
	}
	for _, temp := range []string{filepath.Join(m.config.StateDirectory, ".state.tmp"), filepath.Join(m.config.StateDirectory, "system", ".system-state.tmp")} {
		before[temp] = []byte("preserved inert crash temporary")
		if os.WriteFile(temp, before[temp], 0600) != nil {
			t.Fatal("temp")
		}
	}
	for _, mode := range []string{"preview", "enable", "preview", "disable"} {
		result, e := ConfigureEndpointIdentity(path, mode, mode == "enable")
		if e != nil || !result.ExistingStatePreserved {
			t.Fatal(mode, e)
		}
		if mode == "enable" && !result.Enabled || mode == "disable" && result.Enabled {
			t.Fatal("consent result mismatch")
		}
		for p, want := range before {
			got, e := os.ReadFile(p)
			if e != nil || !bytes.Equal(got, want) {
				t.Fatal("consent command changed ledger/temp")
			}
		}
	}
	marker := filepath.Join(m.config.StateDirectory, "inventory", ".ledger.tmp")
	markerBytes := []byte("uncertain inventory commit remains held")
	if os.WriteFile(marker, markerBytes, 0600) != nil {
		t.Fatal("uncertainty fixture")
	}
	if _, e = ConfigureEndpointIdentity(path, "enable", true); e == nil {
		t.Fatal("inventory uncertainty bypassed")
	}
	got, _ := os.ReadFile(marker)
	if !bytes.Equal(got, markerBytes) {
		t.Fatal("inventory uncertainty marker cleaned")
	}
	for p, want := range before {
		got, e := os.ReadFile(p)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("rejected configuration changed state")
		}
	}
	if network.Load() != 0 {
		t.Fatal("local configuration used network")
	}
	if _, e = ConfigureEndpointIdentity(path, "enable", false); e == nil {
		t.Fatal("unacknowledged enable")
	}
}
func TestEndpointConsentMalformedForeignUnsafeAndMissingStateFailClosed(t *testing.T) {
	f := integrationFixture(t, "tls", nil)
	m, path := prepareEndpointHandoff(t, f.material)
	for _, raw := range [][]byte{[]byte(`{}`), []byte(`{"acknowledged":true}`), []byte(`not json`)} {
		if os.WriteFile(endpointConsentPath(m), raw, 0600) != nil {
			t.Fatal("fixture")
		}
		if _, ok := readEndpointConsent(m); ok {
			t.Fatal("malformed consent enabled")
		}
	}
	if os.Remove(endpointConsentPath(m)) != nil {
		t.Fatal("fixture cleanup")
	}
	target := filepath.Join(filepath.Dir(path), "unrelated")
	if os.WriteFile(target, []byte("preserve"), 0600) != nil || os.Symlink(target, endpointConsentPath(m)) != nil {
		t.Fatal("symlink fixture")
	}
	if _, ok := readEndpointConsent(m); ok {
		t.Fatal("symlink consent enabled")
	}
	if _, e := ConfigureEndpointIdentity(path, "enable", true); e == nil {
		t.Fatal("symlink overwritten")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "preserve" {
		t.Fatal("symlink target changed")
	}
	os.Remove(endpointConsentPath(m))
	consentFixture(t, m)
	other := m
	other.config.AgentID = "agent_ffeeddccbbaa99887766554433221100"
	other.binding = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if _, ok := readEndpointConsent(other); ok {
		t.Fatal("foreign material enabled")
	}
	dir := systemStateDirectory(m.config)
	if os.Rename(dir, dir+"-preserved") != nil {
		t.Fatal("missing-state fixture")
	}
	if _, e := ConfigureEndpointIdentity(path, "disable", false); e == nil {
		t.Fatal("missing ledger allowed mutation")
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("missing ledger reinitialized")
	}
}
func TestEndpointNativeExactRetryAndDisablePreserveSystemFloor(t *testing.T) {
	for _, profile := range []string{"tls", "http-test"} {
		for _, disable := range []bool{false, true} {
			t.Run(profile+map[bool]string{false: "/retry", true: "/disable"}[disable], func(t *testing.T) {
				var mu sync.Mutex
				var bodies [][]byte
				var verifier *systemwire.Verifier
				var agent string
				f := integrationFixture(t, profile, func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						var raw []byte
						var e error
						if profile == "http-test" {
							v, err := verifier.Verify(r)
							raw, e = v.Body, err
						} else {
							raw, e = io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
						}
						frame, err := systemwire.Decode(raw)
						if e != nil || err != nil {
							t.Error("bad request")
							w.WriteHeader(400)
							return
						}
						mu.Lock()
						bodies = append(bodies, bytes.Clone(raw))
						n := len(bodies)
						mu.Unlock()
						if n == 1 {
							w.WriteHeader(503)
							return
						}
						sum := sha256.Sum256(raw)
						w.Header().Set("Content-Type", "application/json")
						json.NewEncoder(w).Encode(systemwire.Receipt{SchemaVersion: systemwire.ReceiptVersion, DeviceID: agent, Sequence: frame.Sequence, GenerationID: frame.Snapshot.GenerationID, CollectedAt: frame.Snapshot.CollectedAt, ReceivedAt: time.Now().UTC(), BodyHash: hex.EncodeToString(sum[:])})
					})
				})
				m, _ := prepareEndpointHandoff(t, f.material)
				agent = m.config.AgentID
				if profile == "http-test" {
					var e error
					verifier, e = systemwire.New(systemwire.Config{Origin: m.config.ManagerOrigin, Registry: f.registry})
					if e != nil {
						t.Fatal(e)
					}
				}
				consentFixture(t, m)
				var calls atomic.Int32
				sender, e := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
					return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
				}, func() time.Time { return time.Now().UTC() })
				if e != nil {
					t.Fatal(e)
				}
				defer sender.Close()
				sender.identityCollect = func(_ context.Context, id string, at time.Time, _ endpointidentity.LocalConsent, _ string) (endpointidentity.Snapshot, error) {
					calls.Add(1)
					return endpointidentity.Empty(id, at, endpointidentity.ReasonPermissionDenied), nil
				}
				if _, e = sender.Run(context.Background()); e == nil {
					t.Fatal("unacknowledged report succeeded")
				}
				pending, _ := sender.state.Pending()
				if pending == nil {
					t.Fatal("exact body not retained")
				}
				first := pending.Body()
				if disable {
					if os.Remove(endpointConsentPath(m)) != nil {
						t.Fatal("disable fixture")
					}
				}
				if _, e = sender.Run(context.Background()); e != nil {
					t.Fatal(e)
				}
				if calls.Load() != 1 {
					t.Fatal("retry/disable recaptured identity")
				}
				mu.Lock()
				defer mu.Unlock()
				if len(bodies) != 2 {
					t.Fatal("delivery count")
				}
				frame, e := systemwire.Decode(bodies[1])
				if e != nil {
					t.Fatal(e)
				}
				if disable {
					if frame.EndpointIdentity != nil || frame.Sequence != 2 {
						t.Fatal("disabled pending sent or consumed sequence reused")
					}
				} else if !bytes.Equal(first, bodies[1]) || frame.Sequence != 1 {
					t.Fatal("exact pending bytes changed")
				}
			})
		}
	}
}
func TestEndpointNativeConsentRemovedDuringCollectionPreventsAnySend(t *testing.T) {
	var requests atomic.Int32
	f := integrationFixture(t, "tls", func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); next.ServeHTTP(w, r) })
	})
	m, _ := prepareEndpointHandoff(t, f.material)
	consentFixture(t, m)
	sender, e := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
	}, func() time.Time { return time.Now().UTC() })
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	sender.identityCollect = func(_ context.Context, id string, at time.Time, _ endpointidentity.LocalConsent, _ string) (endpointidentity.Snapshot, error) {
		if os.Remove(endpointConsentPath(m)) != nil {
			t.Fatal("disable")
		}
		return endpointidentity.Empty(id, at, endpointidentity.ReasonNotCollected), nil
	}
	report, e := sender.Run(context.Background())
	if e != nil || report.Status != "endpoint_identity_disabled" || requests.Load() != 0 {
		t.Fatal("removed consent still sent", e)
	}
	pending, _ := sender.state.Pending()
	next, _ := sender.state.NextSequence()
	if pending != nil || next != 2 {
		t.Fatal("disabled staged body or floor lost")
	}
}

func TestEndpointConsentRemovedBeforeSourcePreventsEndpointRead(t *testing.T) {
	var identityCalls atomic.Int32
	f := integrationFixture(t, "tls", func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(io.LimitReader(r.Body, systemwire.MaxBodyBytes+1))
			frame, e := systemwire.Decode(raw)
			if e != nil || frame.EndpointIdentity != nil {
				t.Error("removed consent still included identity")
			}
			w.WriteHeader(503)
		})
	})
	m, _ := prepareEndpointHandoff(t, f.material)
	consentFixture(t, m)
	sender, e := openSystemSenderWithSource(m, func(_ context.Context, id string, at time.Time) (systeminventory.Snapshot, error) {
		if os.Remove(endpointConsentPath(m)) != nil {
			t.Fatal("disable fixture")
		}
		return systeminventory.Empty(id, at, systeminventory.ReasonNotCollected), nil
	}, func() time.Time { return time.Now().UTC() })
	if e != nil {
		t.Fatal(e)
	}
	defer sender.Close()
	sender.identityCollect = func(_ context.Context, id string, at time.Time, _ endpointidentity.LocalConsent, _ string) (endpointidentity.Snapshot, error) {
		identityCalls.Add(1)
		return endpointidentity.Empty(id, at, endpointidentity.ReasonNotCollected), nil
	}
	if _, e = sender.Run(context.Background()); e == nil || identityCalls.Load() != 0 {
		t.Fatal("endpoint read after consent removal")
	}
}
